// Command oidc-manager-auth-e2e exercises Manager OIDC auth against a live
// Manager using a real GitHub Actions ID token and real GitHub JWKS.
//
// Modes (E2E_MODE):
//   - quick (default): FetchConfig + ForceRefresh + reject matrix
//   - long-remint: sleep past ID-token lifetime (~300s) and prove automatic
//     remint via ReuseTokenSourceWithExpiry (new iat/exp), then ForceRefresh
//   - full: long-remint + IngestLog to a configured sink + reject matrix
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
)

type result struct {
	Name    string         `json:"name"`
	OK      bool           `json:"ok"`
	Detail  string         `json:"detail,omitempty"`
	Code    string         `json:"connect_code,omitempty"`
	Elapsed string         `json:"elapsed,omitempty"`
	Extra   map[string]any `json:"extra,omitempty"`
}

type jwtTimes struct {
	Iat              int64  `json:"iat"`
	Exp              int64  `json:"exp"`
	LifetimeSeconds int64  `json:"lifetime_seconds"`
	Iss              string `json:"iss,omitempty"`
	Aud              any    `json:"aud,omitempty"`
	RawPrefix        string `json:"raw_prefix,omitempty"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := context.Background()

	mode := strings.ToLower(strings.TrimSpace(envOr("E2E_MODE", "quick")))
	managerURL := envOr("MANAGER_URL", "http://127.0.0.1:18080")
	denyURL := envOr("MANAGER_DENY_URL", "http://127.0.0.1:18081")
	audience := envOr("MANAGER_AUDIENCE", managerURL)
	repo := envOr("GITHUB_REPOSITORY", "")
	sleepSec := envInt("E2E_SLEEP_SECONDS", 330)
	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqTok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if repo == "" || reqURL == "" || reqTok == "" {
		fail("missing GITHUB_REPOSITORY or ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN (must run in Actions with id-token: write)")
	}

	results := []result{}
	pass := true
	record := func(r result) {
		results = append(results, r)
		logger.Info("step", "name", r.Name, "ok", r.OK, "detail", r.Detail, "code", r.Code, "extra", r.Extra)
		if !r.OK {
			pass = false
		}
	}

	// 1) request_url host allowlist
	start := time.Now()
	err := managerclient.ValidateIDTokenRequestURL(reqURL, managerclient.DefaultIDTokenRequestURLHosts)
	r := result{Name: "request_url_host_allowlist", Elapsed: time.Since(start).String()}
	if err != nil {
		r.OK = false
		r.Detail = err.Error()
	} else {
		r.OK = true
		r.Detail = "host matched *.actions.githubusercontent.com"
	}
	record(r)

	start = time.Now()
	err = managerclient.ValidateIDTokenRequestURL("https://169.254.169.254/latest/meta-data", managerclient.DefaultIDTokenRequestURLHosts)
	r = result{Name: "request_url_host_reject_ssrf", Elapsed: time.Since(start).String()}
	if err == nil {
		r.OK = false
		r.Detail = "expected reject for metadata host"
	} else {
		r.OK = true
		r.Detail = err.Error()
	}
	record(r)

	start = time.Now()
	err = managerclient.ValidateIDTokenRequestURL("http://run-actions-1-azure-eastus.actions.githubusercontent.com/token", managerclient.DefaultIDTokenRequestURLHosts)
	r = result{Name: "request_url_https_only", Elapsed: time.Since(start).String()}
	if err == nil {
		r.OK = false
		r.Detail = "expected reject for http scheme"
	} else {
		r.OK = true
		r.Detail = err.Error()
	}
	record(r)

	conn := managerclient.NewOIDCConnection(managerURL, reqURL, reqTok, audience, nil)
	client, err := managerclient.NewConfigClient(logger, conn)
	if err != nil {
		fail("NewConfigClient: " + err.Error())
	}

	identity := jobIdentity(repo)
	req := &managerv1beta1.FetchConfigRequest{JobIdentity: identity}

	// 2) FetchConfig with real ID token
	start = time.Now()
	fr, err := client.FetchConfig(ctx, req)
	r = result{Name: "fetch_config_allowlisted", Elapsed: time.Since(start).String()}
	beforeTok, beforeTimes, beforeErr := peekJWT(conn)
	if err != nil {
		r.OK = false
		r.Detail = err.Error()
		if rpc, ok := err.(*managerclient.RPCError); ok {
			r.Code = rpc.Code.String()
		}
	} else {
		r.OK = true
		r.Detail = fmt.Sprintf("config_revision=%s rule_sources=%d", fr.ConfigRevision, len(fr.RuleSources))
		r.Extra = map[string]any{"jwt_before": beforeTimes, "peek_err": errString(beforeErr)}
	}
	record(r)

	doLongRemint := mode == "long-remint" || mode == "full"
	doIngest := mode == "full" || envOr("E2E_INGEST", "") == "1"
	doRejects := mode != "long-remint" || envOr("E2E_REJECTS", "1") == "1"

	if doLongRemint {
		logger.Info("long_remint_sleep_begin", "seconds", sleepSec, "jwt_before", beforeTimes)
		time.Sleep(time.Duration(sleepSec) * time.Second)
		logger.Info("long_remint_sleep_end")

		// Automatic remint path: do NOT call ForceRefresh. FetchConfig must
		// pull a fresh JWT through ReuseTokenSourceWithExpiry because the
		// prior ID token (lifetime ~300s) is expired.
		start = time.Now()
		r = result{Name: "auto_remint_after_id_token_expiry", Elapsed: ""}
		fr2, err := client.FetchConfig(ctx, req)
		afterTok, afterTimes, afterErr := peekJWT(conn)
		r.Elapsed = time.Since(start).String()
		r.Extra = map[string]any{
			"sleep_seconds": sleepSec,
			"jwt_before":    beforeTimes,
			"jwt_after":     afterTimes,
			"peek_before_err": errString(beforeErr),
			"peek_after_err":  errString(afterErr),
		}
		if err != nil {
			r.OK = false
			r.Detail = err.Error()
			if rpc, ok := err.(*managerclient.RPCError); ok {
				r.Code = rpc.Code.String()
			}
		} else if beforeTimes == nil || afterTimes == nil {
			r.OK = false
			r.Detail = "missing jwt iat/exp before or after remint"
		} else if afterTimes.Iat <= beforeTimes.Iat {
			r.OK = false
			r.Detail = fmt.Sprintf("expected newer iat after remint; before=%d after=%d", beforeTimes.Iat, afterTimes.Iat)
		} else if afterTok == beforeTok {
			r.OK = false
			r.Detail = "token string unchanged after expiry sleep (no remint)"
		} else {
			r.OK = true
			r.Detail = fmt.Sprintf("ReuseTokenSourceWithExpiry reminted; iat %d→%d exp %d→%d; config_revision=%s",
				beforeTimes.Iat, afterTimes.Iat, beforeTimes.Exp, afterTimes.Exp, fr2.ConfigRevision)
		}
		record(r)

		// Capture post-remint baseline for ForceRefresh comparison.
		beforeTok, beforeTimes, beforeErr = afterTok, afterTimes, afterErr
	}

	// 3) ForceRefresh (project-result / shutdown Summary path)
	start = time.Now()
	r = result{Name: "force_refresh_remint_then_fetch", Elapsed: ""}
	forcedBefore, forcedBeforeTimes, _ := peekJWT(conn)
	if err := conn.ForceRefreshIDToken(ctx); err != nil {
		r.OK = false
		r.Detail = "ForceRefresh: " + err.Error()
	} else if fr3, err := client.FetchConfig(ctx, req); err != nil {
		r.OK = false
		r.Detail = err.Error()
		if rpc, ok := err.(*managerclient.RPCError); ok {
			r.Code = rpc.Code.String()
		}
	} else {
		forcedAfter, forcedAfterTimes, _ := peekJWT(conn)
		r.OK = true
		r.Detail = fmt.Sprintf("ForceRefresh pinned JWT; config_revision=%s", fr3.ConfigRevision)
		r.Extra = map[string]any{
			"jwt_before_force": forcedBeforeTimes,
			"jwt_after_force":  forcedAfterTimes,
			"token_changed":    forcedBefore != forcedAfter,
		}
		_ = beforeErr
	}
	r.Elapsed = time.Since(start).String()
	record(r)

	if doIngest {
		collector := managerclient.NewCollectorServiceClient(logger, nil, conn)
		start = time.Now()
		r = result{Name: "ingest_log_oidc", Elapsed: ""}
		err := collector.SendLogBatch(ctx, managerclient.LogBatch{
			Identity: jobcontext.GitHubJobIdentity(
				"github.com",
				repo,
				envOr("GITHUB_RUN_ID", "1"),
				envOr("GITHUB_JOB", "e2e"),
				envOr("GITHUB_RUN_ATTEMPT", "1"),
				envOr("RUNNER_TRACKING_ID", "e2e-runner"),
			),
			Scope:   managerv1beta1.Scope_SCOPE_PROJECT,
			Type:    managerv1beta1.LogType_LOG_TYPE_SUMMARY,
			Records: [][]byte{[]byte(`{"e2e":"oidc-manager-auth","kind":"summary"}`)},
			FlushAt: time.Now().UTC(),
		})
		if err != nil {
			r.OK = false
			r.Detail = err.Error()
			if rpc, ok := err.(*managerclient.RPCError); ok {
				r.Code = rpc.Code.String()
			}
		} else {
			r.OK = true
			r.Detail = "IngestLog accepted with id-token auth to configured sink"
		}
		r.Elapsed = time.Since(start).String()
		record(r)
	}

	if doRejects {
		start = time.Now()
		badPath := &managerv1beta1.FetchConfigRequest{JobIdentity: jobIdentity("other-org/not-allowed")}
		_, err = client.FetchConfig(ctx, badPath)
		r = result{Name: "reject_project_path_mismatch", Elapsed: time.Since(start).String()}
		if err == nil {
			r.OK = false
			r.Detail = "expected permission_denied"
		} else if rpc, ok := err.(*managerclient.RPCError); ok && rpc.Code == connect.CodePermissionDenied {
			r.OK = true
			r.Code = rpc.Code.String()
			r.Detail = "permission_denied as expected"
		} else {
			r.OK = false
			r.Detail = err.Error()
			if rpc, ok := err.(*managerclient.RPCError); ok {
				r.Code = rpc.Code.String()
			}
		}
		record(r)

		start = time.Now()
		_, err = client.FetchConfig(ctx, &managerv1beta1.FetchConfigRequest{})
		r = result{Name: "reject_missing_job_identity", Elapsed: time.Since(start).String()}
		if err == nil {
			r.OK = false
			r.Detail = "expected permission_denied"
		} else if rpc, ok := err.(*managerclient.RPCError); ok &&
			(rpc.Code == connect.CodePermissionDenied || rpc.Code == connect.CodeInvalidArgument) {
			r.OK = true
			r.Code = rpc.Code.String()
			r.Detail = "rejected as expected (" + rpc.Code.String() + ")"
		} else {
			r.OK = false
			r.Detail = err.Error()
			if rpc, ok := err.(*managerclient.RPCError); ok {
				r.Code = rpc.Code.String()
			}
		}
		record(r)

		denyConn := managerclient.NewOIDCConnection(denyURL, reqURL, reqTok, audience, nil)
		denyClient, err := managerclient.NewConfigClient(logger, denyConn)
		if err != nil {
			fail("deny NewConfigClient: " + err.Error())
		}
		start = time.Now()
		_, err = denyClient.FetchConfig(ctx, req)
		r = result{Name: "reject_wrong_allowlist", Elapsed: time.Since(start).String()}
		if err == nil {
			r.OK = false
			r.Detail = "expected unauthenticated against deny-allowlist Manager"
		} else if rpc, ok := err.(*managerclient.RPCError); ok && rpc.Code == connect.CodeUnauthenticated {
			r.OK = true
			r.Code = rpc.Code.String()
			r.Detail = "unauthenticated as expected (allowlist miss)"
		} else {
			r.OK = false
			r.Detail = err.Error()
			if rpc, ok := err.(*managerclient.RPCError); ok {
				r.Code = rpc.Code.String()
			}
		}
		record(r)
	}

	proven := []string{
		"ACTIONS_ID_TOKEN_REQUEST_URL host allowlist + https-only",
		"GET mint real GitHub Actions ID token",
		"Cicd-Sensor-Token-Type: id-token + Authorization Bearer JWT",
		"Manager verify via go-oidc RemoteKeySet (real GitHub JWKS)",
		"exact-claim allowlist match",
		"JobIdentity bind (provider+project_path)",
		"FetchConfig success",
		"ForceRefresh remint then FetchConfig (shutdown Summary path)",
	}
	if doLongRemint {
		proven = append(proven, "ReuseTokenSourceWithExpiry auto-remint after ID token expiry with new iat/exp")
	}
	if doIngest {
		proven = append(proven, "IngestLog with OIDC to configured sink")
	}
	if doRejects {
		proven = append(proven,
			"reject wrong project_path",
			"reject missing JobIdentity",
			"reject wrong allowlist",
		)
	}

	out := map[string]any{
		"ok":               pass,
		"mode":             mode,
		"manager_url":      managerURL,
		"manager_deny_url": denyURL,
		"audience":         audience,
		"repository":       repo,
		"issuer":           "https://token.actions.githubusercontent.com",
		"jwks_url":         "https://token.actions.githubusercontent.com/.well-known/jwks",
		"sleep_seconds":    sleepSec,
		"proven":           proven,
		"results":          results,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)

	path := envOr("E2E_RESULTS_PATH", "/tmp/oidc-manager-auth-e2e/results.json")
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	if f, err := os.Create(path); err == nil {
		_ = json.NewEncoder(f).Encode(out)
		_ = f.Close()
	}

	if !pass {
		os.Exit(1)
	}
}

func peekJWT(conn managerclient.Connection) (raw string, times *jwtTimes, err error) {
	if conn.Cached == nil {
		return "", nil, fmt.Errorf("no cached token source")
	}
	tok, err := conn.Cached.Token()
	if err != nil {
		return "", nil, err
	}
	raw = tok.AccessToken
	times, err = decodeJWTTimes(raw)
	return raw, times, err
}

func decodeJWTTimes(raw string) (*jwtTimes, error) {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
		Aud any    `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	prefix := raw
	if len(prefix) > 24 {
		prefix = prefix[:24]
	}
	return &jwtTimes{
		Iat:              claims.Iat,
		Exp:              claims.Exp,
		LifetimeSeconds: claims.Exp - claims.Iat,
		Iss:              claims.Iss,
		Aud:              claims.Aud,
		RawPrefix:        prefix,
	}, nil
}

func jobIdentity(projectPath string) *managerv1beta1.JobIdentity {
	return &managerv1beta1.JobIdentity{
		Provider:               "github",
		ProviderHost:           "github.com",
		ProjectPath:            projectPath,
		GithubRunId:            envOr("GITHUB_RUN_ID", "1"),
		GithubJob:              envOr("GITHUB_JOB", "e2e"),
		GithubRunAttempt:       envOr("GITHUB_RUN_ATTEMPT", "1"),
		GithubRunnerTrackingId: envOr("RUNNER_TRACKING_ID", "e2e-runner"),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n <= 0 {
		return def
	}
	return n
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

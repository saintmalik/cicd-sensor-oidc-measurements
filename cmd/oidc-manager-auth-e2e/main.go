// Command oidc-manager-auth-e2e exercises Stage 1 Manager OIDC auth against a
// live Manager using a real GitHub Actions ID token (minted via
// ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN) and real GitHub JWKS verification.
//
// Intended to run inside GitHub Actions with permissions.id-token: write and a
// same-job colocated Manager. Not a fake-issuer unit test.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
)

type result struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail,omitempty"`
	Code    string `json:"connect_code,omitempty"`
	Elapsed string `json:"elapsed,omitempty"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := context.Background()

	managerURL := envOr("MANAGER_URL", "http://127.0.0.1:18080")
	denyURL := envOr("MANAGER_DENY_URL", "http://127.0.0.1:18081")
	audience := envOr("MANAGER_AUDIENCE", managerURL)
	repo := envOr("GITHUB_REPOSITORY", "")
	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqTok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if repo == "" || reqURL == "" || reqTok == "" {
		fail("missing GITHUB_REPOSITORY or ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN (must run in Actions with id-token: write)")
	}

	results := []result{}
	pass := true

	// 1) request_url host allowlist (Agent startup check before mint)
	start := time.Now()
	err := managerclient.ValidateIDTokenRequestURL(reqURL, managerclient.DefaultIDTokenRequestURLHosts)
	r := result{Name: "request_url_host_allowlist", Elapsed: time.Since(start).String()}
	if err != nil {
		r.OK = false
		r.Detail = err.Error()
		pass = false
	} else {
		r.OK = true
		r.Detail = "host matched *.actions.githubusercontent.com"
	}
	results = append(results, r)
	logger.Info("step", "name", r.Name, "ok", r.OK, "detail", r.Detail)

	// Negative: bad request_url host must reject
	start = time.Now()
	err = managerclient.ValidateIDTokenRequestURL("https://169.254.169.254/latest/meta-data", managerclient.DefaultIDTokenRequestURLHosts)
	r = result{Name: "request_url_host_reject_ssrf", Elapsed: time.Since(start).String()}
	if err == nil {
		r.OK = false
		r.Detail = "expected reject for metadata host"
		pass = false
	} else {
		r.OK = true
		r.Detail = err.Error()
	}
	results = append(results, r)

	conn := managerclient.NewOIDCConnection(managerURL, reqURL, reqTok, audience, nil)
	client, err := managerclient.NewConfigClient(logger, conn)
	if err != nil {
		fail("NewConfigClient: " + err.Error())
	}

	identity := jobIdentity(repo)
	req := &managerv1beta1.FetchConfigRequest{JobIdentity: identity}

	// 2) FetchConfig with real ID token + real JWKS + matching allowlist
	start = time.Now()
	fr, err := client.FetchConfig(ctx, req)
	r = result{Name: "fetch_config_allowlisted", Elapsed: time.Since(start).String()}
	if err != nil {
		r.OK = false
		r.Detail = err.Error()
		if rpc, ok := err.(*managerclient.RPCError); ok {
			r.Code = rpc.Code.String()
		}
		pass = false
	} else {
		r.OK = true
		r.Detail = fmt.Sprintf("config_revision=%s rule_sources=%d", fr.ConfigRevision, len(fr.RuleSources))
	}
	results = append(results, r)
	logger.Info("step", "name", r.Name, "ok", r.OK, "detail", r.Detail, "code", r.Code)

	// 3) ForceRefresh (project-result remint path) then FetchConfig again
	start = time.Now()
	r = result{Name: "force_refresh_remint_then_fetch", Elapsed: ""}
	if err := conn.ForceRefreshIDToken(ctx); err != nil {
		r.OK = false
		r.Detail = "ForceRefresh: " + err.Error()
		pass = false
	} else if fr2, err := client.FetchConfig(ctx, req); err != nil {
		r.OK = false
		r.Detail = err.Error()
		if rpc, ok := err.(*managerclient.RPCError); ok {
			r.Code = rpc.Code.String()
		}
		pass = false
	} else {
		r.OK = true
		r.Detail = fmt.Sprintf("reminted; config_revision=%s", fr2.ConfigRevision)
	}
	r.Elapsed = time.Since(start).String()
	results = append(results, r)
	logger.Info("step", "name", r.Name, "ok", r.OK, "detail", r.Detail)

	// 4) Negative: wrong JobIdentity.project_path -> permission_denied
	start = time.Now()
	badPath := &managerv1beta1.FetchConfigRequest{JobIdentity: jobIdentity("other-org/not-allowed")}
	_, err = client.FetchConfig(ctx, badPath)
	r = result{Name: "reject_project_path_mismatch", Elapsed: time.Since(start).String()}
	if err == nil {
		r.OK = false
		r.Detail = "expected permission_denied"
		pass = false
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
		pass = false
	}
	results = append(results, r)

	// 5) Negative: missing JobIdentity -> permission_denied (OIDC bind)
	start = time.Now()
	_, err = client.FetchConfig(ctx, &managerv1beta1.FetchConfigRequest{})
	r = result{Name: "reject_missing_job_identity", Elapsed: time.Since(start).String()}
	if err == nil {
		r.OK = false
		r.Detail = "expected permission_denied"
		pass = false
	} else if rpc, ok := err.(*managerclient.RPCError); ok && rpc.Code == connect.CodePermissionDenied {
		r.OK = true
		r.Code = rpc.Code.String()
		r.Detail = "permission_denied as expected"
	} else {
		// Handler may return InvalidArgument if interceptor order differs; still a reject.
		if rpc, ok := err.(*managerclient.RPCError); ok &&
			(rpc.Code == connect.CodeInvalidArgument || rpc.Code == connect.CodePermissionDenied) {
			r.OK = true
			r.Code = rpc.Code.String()
			r.Detail = "rejected as expected (" + rpc.Code.String() + ")"
		} else {
			r.OK = false
			r.Detail = err.Error()
			if rpc, ok := err.(*managerclient.RPCError); ok {
				r.Code = rpc.Code.String()
			}
			pass = false
		}
	}
	results = append(results, r)

	// 6) Negative: Manager with wrong allowlist rejects valid token (401)
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
		pass = false
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
		pass = false
	}
	results = append(results, r)
	logger.Info("step", "name", r.Name, "ok", r.OK, "detail", r.Detail, "code", r.Code)

	out := map[string]any{
		"ok":                 pass,
		"manager_url":        managerURL,
		"manager_deny_url":   denyURL,
		"audience":           audience,
		"repository":         repo,
		"issuer":             "https://token.actions.githubusercontent.com",
		"jwks_url":           "https://token.actions.githubusercontent.com/.well-known/jwks",
		"proven": []string{
			"ACTIONS_ID_TOKEN_REQUEST_URL host allowlist",
			"GET mint real GitHub Actions ID token",
			"Cicd-Sensor-Token-Type: id-token + Authorization Bearer JWT",
			"Manager verify via go-oidc RemoteKeySet (real GitHub JWKS)",
			"exact-claim allowlist match",
			"JobIdentity bind (provider+project_path)",
			"FetchConfig success",
			"ForceRefresh remint then FetchConfig",
			"reject wrong project_path",
			"reject missing JobIdentity",
			"reject wrong allowlist",
		},
		"results": results,
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

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

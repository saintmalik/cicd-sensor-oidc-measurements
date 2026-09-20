// Command oidc-agent-path-e2e exercises the production listener project-start /
// project-result path with manager_auth=oidc against a live Manager (real
// GitHub ID token + real JWKS). Starts a JobRegistry+Listener without eBPF
// (KernelTracker nil) so GH-hosted runners can run the same control-socket
// code path the Agent uses for OIDC project scope.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/listener"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

type stepResult struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail,omitempty"`
	Elapsed string `json:"elapsed,omitempty"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	managerURL := envOr("MANAGER_URL", "http://127.0.0.1:18080")
	audience := envOr("MANAGER_AUDIENCE", managerURL)
	repo := envOr("GITHUB_REPOSITORY", "")
	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqTok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if repo == "" || reqURL == "" || reqTok == "" {
		fail("missing GITHUB_REPOSITORY or ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN")
	}

	dir := envOr("E2E_SOCKET_DIR", "/tmp/oidc-agent-path-e2e")
	_ = os.MkdirAll(dir, 0o755)
	sock := filepath.Join(dir, "agent.sock")
	_ = os.Remove(sock)

	jr := jobregistry.New(logger)
	jr.SetBaselineLoadForTesting(func(context.Context, *slog.Logger, string) (rulesource.LoadedRules, error) {
		return rulesource.LoadedRules{}, nil
	})
	l := listener.New(listener.Config{
		Logger:                 logger,
		JobRegistry:            jr,
		SocketPath:             sock,
		RunnerType:             "machine",
		Provider:               jobcontext.ProviderGitHub,
		IDTokenRequestURLHosts: nil, // default *.actions.githubusercontent.com
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- l.Serve(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			fail("listener socket did not appear")
		}
		select {
		case err := <-errCh:
			fail("listener failed: " + err.Error())
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}
	logger.Info("listener_ready", "socket", sock)

	client := unixClient(sock)
	results := []stepResult{}
	pass := true
	record := func(r stepResult) {
		results = append(results, r)
		logger.Info("step", "name", r.Name, "ok", r.OK, "detail", r.Detail)
		if !r.OK {
			pass = false
		}
	}

	owner := envOr("GITHUB_REPOSITORY_OWNER", "")
	if owner == "" {
		if i := indexByte(repo, '/'); i >= 0 {
			owner = repo[:i]
		}
	}

	startBody := map[string]any{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              repo,
		"github_run_id":             envOr("GITHUB_RUN_ID", "1"),
		"github_job":                envOr("GITHUB_JOB", "agent-path"),
		"github_run_attempt":        envOr("GITHUB_RUN_ATTEMPT", "1"),
		"github_runner_tracking_id": envOr("RUNNER_TRACKING_ID", "agent-path-e2e"),
		"manager_url":               managerURL,
		"manager_auth":              "oidc",
		"id_token_request_url":      reqURL,
		"id_token_request_token":    reqTok,
		"id_token_audience":         audience,
	}

	// Reject non-allowlisted request_url at project start (startup allowlist, never widened by request).
	start := time.Now()
	bad := copyMap(startBody)
	bad["id_token_request_url"] = "https://169.254.169.254/latest/meta-data/"
	status, body, err := postJSON(client, "/v1/github/project/start", bad)
	r := stepResult{Name: "project_start_reject_bad_request_url", Elapsed: time.Since(start).String()}
	if err != nil {
		r.OK = false
		r.Detail = err.Error()
	} else if status != http.StatusBadRequest {
		r.OK = false
		r.Detail = fmt.Sprintf("status=%d body=%s, want 400", status, truncate(body, 200))
	} else {
		r.OK = true
		r.Detail = truncate(body, 200)
	}
	record(r)

	// project start with real OIDC (FetchConfig via Manager)
	start = time.Now()
	status, body, err = postJSON(client, "/v1/github/project/start", startBody)
	r = stepResult{Name: "project_start_oidc", Elapsed: time.Since(start).String()}
	if err != nil {
		r.OK = false
		r.Detail = err.Error()
	} else if status != http.StatusOK {
		r.OK = false
		r.Detail = fmt.Sprintf("status=%d body=%s", status, truncate(body, 400))
	} else {
		r.OK = true
		r.Detail = "project start ok (manager_auth=oidc → FetchConfig)"
	}
	record(r)

	// project result → ForceRefresh for shutdown Summary JWT pin
	start = time.Now()
	resultBody := map[string]any{
		"provider":                  "github",
		"provider_host":             "github.com",
		"project_path":              repo,
		"github_run_id":             envOr("GITHUB_RUN_ID", "1"),
		"github_job":                envOr("GITHUB_JOB", "agent-path"),
		"github_run_attempt":        envOr("GITHUB_RUN_ATTEMPT", "1"),
		"github_runner_tracking_id": envOr("RUNNER_TRACKING_ID", "agent-path-e2e"),
	}
	status, body, err = postJSON(client, "/v1/github/project/result", resultBody)
	r = stepResult{Name: "project_result_force_refresh", Elapsed: time.Since(start).String()}
	if err != nil {
		r.OK = false
		r.Detail = err.Error()
	} else if status != http.StatusOK {
		r.OK = false
		r.Detail = fmt.Sprintf("status=%d body=%s", status, truncate(body, 400))
	} else {
		r.OK = true
		r.Detail = fmt.Sprintf("project result ok (%d bytes); ForceRefresh path exercised", len(body))
	}
	record(r)

	out := map[string]any{
		"ok":          pass,
		"path":        "listener_project_start_result_no_ebpf",
		"socket":      sock,
		"manager_url": managerURL,
		"audience":    audience,
		"repository":  repo,
		"owner":       owner,
		"proven": []string{
			"listener project start with manager_auth=oidc",
			"request_url host allowlist reject at project start",
			"FetchConfig via OIDC during project start",
			"project result ForceRefresh (shutdown Summary pin)",
		},
		"results": results,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)

	path := envOr("E2E_RESULTS_PATH", filepath.Join(dir, "results.json"))
	if f, err := os.Create(path); err == nil {
		_ = json.NewEncoder(f).Encode(out)
		_ = f.Close()
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
	}

	if !pass {
		os.Exit(1)
	}
}

func unixClient(sock string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
		Timeout: 60 * time.Second,
	}
}

func postJSON(client *http.Client, path string, body any) (int, string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, "", err
	}
	resp, err := client.Post("http://unix"+path, "application/json", bytes.NewReader(payload))
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b), nil
}

func copyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
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

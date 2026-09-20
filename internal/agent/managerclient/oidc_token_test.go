package managerclient_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/oauth2"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1/managerv1beta1connect"
)

func TestValidateIDTokenRequestURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		hosts   []string
		wantErr string
	}{
		{
			name: "allowlisted https host",
			raw:  "https://vstoken.actions.githubusercontent.com/_apis/oidc/oauth2/v2/token?api-version=2.0",
		},
		{
			name:    "http rejected",
			raw:     "http://vstoken.actions.githubusercontent.com/token",
			wantErr: "must use https",
		},
		{
			name:    "non-allowlisted host rejected",
			raw:     "https://169.254.169.254/latest/meta-data",
			wantErr: "not allowlisted",
		},
		{
			name:    "empty rejected",
			raw:     "",
			wantErr: "required",
		},
		{
			name:  "custom allowlist exact host",
			raw:   "https://oidc.ghes.example/token",
			hosts: []string{"oidc.ghes.example"},
		},
		{
			name:    "job cannot use host outside startup allowlist",
			raw:     "https://evil.example/token",
			hosts:   []string{"*.actions.githubusercontent.com"},
			wantErr: "not allowlisted",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := managerclient.ValidateIDTokenRequestURL(tt.raw, tt.hosts)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateIDTokenRequestURL: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateIDTokenRequestURL: got %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestActionsIDTokenSource_GETMint(t *testing.T) {
	var gotMethod, gotAuth, gotAudience string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotAudience = r.URL.Query().Get("audience")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": mintJWT(t, time.Now().Add(5*time.Minute))})
	}))
	t.Cleanup(srv.Close)

	src := &managerclient.ActionsIDTokenSource{
		RequestURL:   srv.URL + "/token",
		RequestToken: "request-secret",
		Audience:     "https://manager.example.com",
		HTTPClient:   srv.Client(),
	}
	tok, err := src.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Fatalf("method: got %q, want GET", gotMethod)
	}
	if gotAuth != "bearer request-secret" {
		t.Fatalf("auth: got %q", gotAuth)
	}
	if gotAudience != "https://manager.example.com" {
		t.Fatalf("audience: got %q", gotAudience)
	}
	if tok.AccessToken == "" {
		t.Fatal("empty access token")
	}
	if tok.Expiry.IsZero() {
		t.Fatal("expected JWT exp to populate token expiry")
	}
}

func TestActionsIDTokenSource_MintFailureUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	src := &managerclient.ActionsIDTokenSource{
		RequestURL:   srv.URL,
		RequestToken: "request-secret",
		Audience:     "https://manager.example.com",
		HTTPClient:   srv.Client(),
	}
	_, err := src.Token()
	if err == nil || !errors.Is(err, managerclient.ErrMintUnavailable) {
		t.Fatalf("Token: got %v, want ErrMintUnavailable", err)
	}
}

func TestReuseIDTokenSource_ConcurrentRefreshCollapsed(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"value": mintJWT(t, time.Now().Add(5*time.Minute)),
		})
	}))
	t.Cleanup(srv.Close)

	inner := &managerclient.ActionsIDTokenSource{
		RequestURL:   srv.URL,
		RequestToken: "request-secret",
		Audience:     "https://manager.example.com",
		HTTPClient:   srv.Client(),
	}
	src := managerclient.NewReuseIDTokenSource(inner)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := src.Token()
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Token: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("mint calls: got %d, want 1 (concurrent refresh collapsed)", got)
	}
}

func TestCachedTokenSource_ForceRefreshForShutdownSummary(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"value": mintJWT(t, time.Now().Add(5*time.Minute)) + "-call-" + strconv.Itoa(int(n)),
		})
	}))
	t.Cleanup(srv.Close)

	inner := &managerclient.ActionsIDTokenSource{
		RequestURL:   srv.URL,
		RequestToken: "request-secret",
		Audience:     "https://manager.example.com",
		HTTPClient:   srv.Client(),
	}
	cached := managerclient.NewCachedTokenSource(inner)

	if err := cached.ForceRefresh(context.Background()); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}
	tok1, err := cached.Token()
	if err != nil {
		t.Fatalf("Token after force: %v", err)
	}
	tok2, err := cached.Token()
	if err != nil {
		t.Fatalf("Token second: %v", err)
	}
	if tok1.AccessToken != tok2.AccessToken {
		t.Fatal("shutdown path must reuse forced JWT without reminting")
	}
	if calls.Load() != 1 {
		t.Fatalf("mint calls after pin: got %d, want 1", calls.Load())
	}
}

func TestConnectClientOptions_TokenTypeHeaders(t *testing.T) {
	if managerclient.TokenTypeManagerToken != "manager-token" {
		t.Fatalf("manager-token value: got %q", managerclient.TokenTypeManagerToken)
	}
	if managerclient.TokenTypeIDToken != "id-token" {
		t.Fatalf("id-token value: got %q", managerclient.TokenTypeIDToken)
	}

	t.Run("manager-token", func(t *testing.T) {
		var gotAuth, gotType string
		svc := &fakeConfigService{
			handler: func(_ context.Context, req *connect.Request[managerv1beta1.FetchConfigRequest]) (*connect.Response[managerv1beta1.FetchConfigResponse], error) {
				gotAuth = req.Header().Get("Authorization")
				gotType = req.Header().Get(managerclient.TokenTypeHeader)
				return connect.NewResponse(&managerv1beta1.FetchConfigResponse{}), nil
			},
		}
		server := newFakeConfigServer(t, svc)
		t.Cleanup(server.Close)

		client := managerv1beta1connect.NewConfigServiceClient(
			managerclient.NewConnectHTTPClient(),
			server.URL,
			managerclient.ConnectClientOptions(testManagerToken)...,
		)
		if _, err := client.FetchConfig(context.Background(), connect.NewRequest(&managerv1beta1.FetchConfigRequest{})); err != nil {
			t.Fatalf("FetchConfig: %v", err)
		}
		if gotAuth != "Bearer "+testManagerToken {
			t.Fatalf("Authorization: got %q", gotAuth)
		}
		if gotType != managerclient.TokenTypeManagerToken {
			t.Fatalf("token type: got %q, want manager-token", gotType)
		}
	})

	t.Run("id-token", func(t *testing.T) {
		var gotAuth, gotType string
		svc := &fakeConfigService{
			handler: func(_ context.Context, req *connect.Request[managerv1beta1.FetchConfigRequest]) (*connect.Response[managerv1beta1.FetchConfigResponse], error) {
				gotAuth = req.Header().Get("Authorization")
				gotType = req.Header().Get(managerclient.TokenTypeHeader)
				return connect.NewResponse(&managerv1beta1.FetchConfigResponse{}), nil
			},
		}
		server := newFakeConfigServer(t, svc)
		t.Cleanup(server.Close)

		src := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "eyJhbGciOiJSUzI1NiJ9.e30.sig"})
		client := managerv1beta1connect.NewConfigServiceClient(
			managerclient.NewConnectHTTPClient(),
			server.URL,
			managerclient.ConnectClientOptionsWithAuth(managerclient.IDTokenAuth(src))...,
		)
		if _, err := client.FetchConfig(context.Background(), connect.NewRequest(&managerv1beta1.FetchConfigRequest{})); err != nil {
			t.Fatalf("FetchConfig: %v", err)
		}
		if gotAuth != "Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig" {
			t.Fatalf("Authorization: got %q", gotAuth)
		}
		if gotType != managerclient.TokenTypeIDToken {
			t.Fatalf("token type: got %q, want id-token", gotType)
		}
	})

	t.Run("mint failure maps to Unavailable", func(t *testing.T) {
		failing := tokenErrSource{err: managerclient.ErrMintUnavailable}
		client := managerv1beta1connect.NewConfigServiceClient(
			managerclient.NewConnectHTTPClient(),
			"http://127.0.0.1:1",
			managerclient.ConnectClientOptionsWithAuth(managerclient.IDTokenAuth(failing))...,
		)
		_, err := client.FetchConfig(context.Background(), connect.NewRequest(&managerv1beta1.FetchConfigRequest{}))
		if err == nil {
			t.Fatal("expected error")
		}
		var connectErr *connect.Error
		if !errors.As(err, &connectErr) || connectErr.Code() != connect.CodeUnavailable {
			t.Fatalf("error: got %v, want Unavailable", err)
		}
	})
}

type tokenErrSource struct{ err error }

func (s tokenErrSource) Token() (*oauth2.Token, error) { return nil, s.err }

func mintJWT(t *testing.T, exp time.Time) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix())))
	return header + "." + payload + ".sig"
}

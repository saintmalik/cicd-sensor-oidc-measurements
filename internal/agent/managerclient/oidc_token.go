package managerclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	// DefaultIDTokenEarlyExpiry is how far before JWT exp the reuse source
	// refreshes. Matches the design's ReuseTokenSourceWithExpiry(60s).
	DefaultIDTokenEarlyExpiry = 60 * time.Second

	// TokenTypeHeader declares which credential kind Authorization carries.
	TokenTypeHeader = "Cicd-Sensor-Token-Type"
	TokenTypeManagerToken = "manager-token"
	TokenTypeIDToken      = "id-token"
)

// ErrMintUnavailable is returned when the Actions ID token mint request fails.
// Callers map it to Connect Unavailable so Agent retry/backoff applies.
var ErrMintUnavailable = fmt.Errorf("id token mint unavailable")

// ActionsIDTokenSource mints GitHub Actions OIDC ID tokens via GET to the
// runner token service (same shape as cosign / actions/toolkit).
type ActionsIDTokenSource struct {
	RequestURL   string
	RequestToken string
	Audience     string
	HTTPClient   *http.Client

	mu sync.Mutex
}

// Token implements oauth2.TokenSource.
func (s *ActionsIDTokenSource) Token() (*oauth2.Token, error) {
	return s.TokenContext(context.Background())
}

// TokenContext mints an ID token using ctx for cancellation.
func (s *ActionsIDTokenSource) TokenContext(ctx context.Context) (*oauth2.Token, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: token source is nil", ErrMintUnavailable)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	mintURL, err := buildMintURL(s.RequestURL, s.Audience)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMintUnavailable, err)
	}
	client := s.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mintURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMintUnavailable, err)
	}
	req.Header.Set("Authorization", "bearer "+s.RequestToken)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMintUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read mint response: %v", ErrMintUnavailable, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: mint status %d", ErrMintUnavailable, resp.StatusCode)
	}

	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: decode mint response: %v", ErrMintUnavailable, err)
	}
	if payload.Value == "" {
		return nil, fmt.Errorf("%w: empty id token", ErrMintUnavailable)
	}

	tok := &oauth2.Token{AccessToken: payload.Value, TokenType: "Bearer"}
	if exp, ok := jwtExpiry(payload.Value); ok {
		tok.Expiry = exp
	}
	return tok, nil
}

func buildMintURL(requestURL, audience string) (string, error) {
	if strings.TrimSpace(requestURL) == "" {
		return "", fmt.Errorf("request_url is required")
	}
	if strings.TrimSpace(audience) == "" {
		return "", fmt.Errorf("audience is required")
	}
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("parse request_url: %w", err)
	}
	q := parsed.Query()
	q.Set("audience", audience)
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

func jwtExpiry(raw string) (time.Time, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Expiry int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, false
	}
	if claims.Expiry <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Expiry, 0), true
}

// NewReuseIDTokenSource wraps a mint source with early refresh (~60s) and
// serialized concurrent refreshes via oauth2.ReuseTokenSourceWithExpiry.
func NewReuseIDTokenSource(src oauth2.TokenSource) oauth2.TokenSource {
	return oauth2.ReuseTokenSourceWithExpiry(nil, src, DefaultIDTokenEarlyExpiry)
}

// CachedTokenSource holds a forced token for shutdown Summary paths when
// fresh minting may no longer work. ForceRefresh always mints via the raw
// mint source (bypassing ReuseTokenSourceWithExpiry); Token returns the
// pinned JWT without re-minting until ForceRefresh is called again.
type CachedTokenSource struct {
	mu    sync.Mutex
	token *oauth2.Token
	mint  oauth2.TokenSource
	reuse oauth2.TokenSource
}

// NewCachedTokenSource wraps a mint source with reuse (~60s early expiry) and
// optional force-remint / pin behavior for shutdown Summary.
func NewCachedTokenSource(mint oauth2.TokenSource) *CachedTokenSource {
	return &CachedTokenSource{
		mint:  mint,
		reuse: NewReuseIDTokenSource(mint),
	}
}

// ForceRefresh mints immediately (bypassing the reuse cache) and pins the
// result for later Token calls. Used by project result before VM shutdown Summary.
func (c *CachedTokenSource) ForceRefresh(ctx context.Context) error {
	if c == nil || c.mint == nil {
		return fmt.Errorf("%w: cached token source is nil", ErrMintUnavailable)
	}
	var tok *oauth2.Token
	var err error
	if ctxSrc, ok := c.mint.(interface {
		TokenContext(context.Context) (*oauth2.Token, error)
	}); ok {
		tok, err = ctxSrc.TokenContext(ctx)
	} else {
		tok, err = c.mint.Token()
	}
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.token = tok
	c.mu.Unlock()
	return nil
}

// Token returns the pinned token when present; otherwise delegates to the
// reuse source (refresh when under ~60s remain).
func (c *CachedTokenSource) Token() (*oauth2.Token, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: cached token source is nil", ErrMintUnavailable)
	}
	c.mu.Lock()
	tok := c.token
	c.mu.Unlock()
	if tok != nil && tok.AccessToken != "" {
		return tok, nil
	}
	if c.reuse == nil {
		return nil, fmt.Errorf("%w: no token source", ErrMintUnavailable)
	}
	return c.reuse.Token()
}

// NewOIDCConnection builds a manager Connection that mints GitHub Actions ID
// tokens, reuses them with a 60s early refresh, and supports ForceRefresh for
// shutdown Summary.
func NewOIDCConnection(baseURL, requestURL, requestToken, audience string, httpClient *http.Client) Connection {
	mint := &ActionsIDTokenSource{
		RequestURL:   requestURL,
		RequestToken: requestToken,
		Audience:     audience,
		HTTPClient:   httpClient,
	}
	cached := NewCachedTokenSource(mint)
	return Connection{
		BaseURL: baseURL,
		Auth:    IDTokenAuth(cached),
		Cached:  cached,
	}
}

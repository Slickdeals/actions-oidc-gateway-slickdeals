package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const allowedOrg = "Slickdeals"

// Leave empty to allow all repos in the org.
// Populate to restrict to specific repos (just the repo name, not "org/repo").
var allowedRepos = []string{}

// Stamped via -ldflags "-X main.version=<tag>" at build time. Exposed in
// /metrics and on the startup log so dashboards can pin to a release.
var version = "dev"

// Process-wide counters and structured logger. Counters are monotonic and
// reset on task restart, which is the standard Prometheus model; scrapers
// handle resets via rate() / increase().
//
// logger defaults to discard so unit tests don't spam stdout. main() swaps
// in a JSON handler on startup.
var (
	logger             = slog.New(slog.NewJSONHandler(io.Discard, nil))
	connectionsAllowed atomic.Uint64
	connectionsDenied  atomic.Uint64
	bytesIn            atomic.Uint64 // runner -> target
	bytesOut           atomic.Uint64 // target -> runner
)

type JWK struct {
	N   string
	Kty string
	Kid string
	Alg string
	E   string
	Use string
	X5c []string
	X5t string
}

type JWKS struct {
	Keys []JWK
}

type GatewayContext struct {
	jwksCache      []byte
	jwksLastUpdate time.Time
}

func getKeyFromJwks(jwksBytes []byte) func(*jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		var jwks JWKS
		if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
			return nil, fmt.Errorf("Unable to parse JWKS")
		}

		for _, jwk := range jwks.Keys {
			if jwk.Kid == token.Header["kid"] {
				nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
				if err != nil {
					return nil, fmt.Errorf("Unable to parse key")
				}
				var n big.Int

				eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
				if err != nil {
					return nil, fmt.Errorf("Unable to parse key")
				}
				var e big.Int

				key := rsa.PublicKey{
					N: n.SetBytes(nBytes),
					E: int(e.SetBytes(eBytes).Uint64()),
				}

				return &key, nil
			}
		}

		return nil, fmt.Errorf("Unknown kid: %v", token.Header["kid"])
	}
}

func validateTokenCameFromGitHub(oidcTokenString string, gc *GatewayContext) (jwt.MapClaims, error) {
	// Check if we have a recently cached JWKS
	now := time.Now()

	if now.Sub(gc.jwksLastUpdate) > time.Minute || len(gc.jwksCache) == 0 {
		resp, err := http.Get("https://token.actions.githubusercontent.com/.well-known/jwks")
		if err != nil {
			return nil, fmt.Errorf("Unable to get JWKS configuration: %w", err)
		}

		jwksBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("Unable to read JWKS body: %w", err)
		}

		gc.jwksCache = jwksBytes
		gc.jwksLastUpdate = now
	}

	// Attempt to validate JWT with JWKS
	oidcToken, err := jwt.Parse(string(oidcTokenString), getKeyFromJwks(gc.jwksCache))
	if err != nil || !oidcToken.Valid {
		return nil, fmt.Errorf("Unable to validate JWT")
	}

	claims, ok := oidcToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("Unable to map JWT claims")
	}

	return claims, nil
}

// transfer copies one direction of a hijacked tunnel and adds the byte count
// to counter. Closes both ends when copy returns.
func transfer(dst io.WriteCloser, src io.ReadCloser, counter *atomic.Uint64) int64 {
	defer dst.Close()
	defer src.Close()
	n, _ := io.Copy(dst, src)
	counter.Add(uint64(n))
	return n
}

// safeStr returns claims[key] as a string, or "" if absent or wrong type.
// Keeps log attrs uniform without crashing on malformed claims.
func safeStr(claims jwt.MapClaims, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

// requestAttrs are the connection-level fields on every request log.
func requestAttrs(req *http.Request) []any {
	return []any{
		"remote_addr", req.RemoteAddr,
		"method", req.Method,
		"target", req.Host,
	}
}

// claimAttrs are the JWT-derived fields on logs for requests that got far
// enough to parse a token. Never logs the token itself.
func claimAttrs(claims jwt.MapClaims) []any {
	return []any{
		"repo_owner", safeStr(claims, "repository_owner"),
		"repository", safeStr(claims, "repository"),
		"workflow", safeStr(claims, "workflow"),
		"run_id", safeStr(claims, "run_id"),
		"actor", safeStr(claims, "actor"),
		"ref", safeStr(claims, "ref"),
	}
}

// deny increments the denied counter, logs at WARN with structured fields,
// and writes 401 to the client. extra is appended to the log attrs.
func deny(w http.ResponseWriter, req *http.Request, reason string, extra ...any) {
	connectionsDenied.Add(1)
	attrs := append([]any{"outcome", "denied", "deny_reason", reason}, requestAttrs(req)...)
	attrs = append(attrs, extra...)
	logger.Warn("request_decision", attrs...)
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func handleProxyRequest(w http.ResponseWriter, req *http.Request, claims jwt.MapClaims) {
	target := req.Host
	remote := req.RemoteAddr

	proxyConn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		logger.Error("tunnel_dial_failed",
			"remote_addr", remote, "target", target, "err", err.Error(),
			"repository", safeStr(claims, "repository"))
		http.Error(w, http.StatusText(http.StatusRequestTimeout), http.StatusRequestTimeout)
		return
	}

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		proxyConn.Close()
		logger.Error("hijack_unsupported", "remote_addr", remote, "target", target)
		http.Error(w, http.StatusText(http.StatusExpectationFailed), http.StatusExpectationFailed)
		return
	}

	reqConn, _, err := hijacker.Hijack()
	if err != nil {
		proxyConn.Close()
		logger.Error("hijack_failed", "remote_addr", remote, "target", target, "err", err.Error())
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	start := time.Now()
	repository := safeStr(claims, "repository")
	inDone := make(chan int64, 1)
	outDone := make(chan int64, 1)

	go func() { inDone <- transfer(proxyConn, reqConn, &bytesIn) }()
	go func() { outDone <- transfer(reqConn, proxyConn, &bytesOut) }()

	// Tunnel-close logger. Uses Background because the request handler has
	// long since returned (the connection was hijacked) — req.Context() may
	// already be cancelled.
	go func() {
		in := <-inDone
		out := <-outDone
		logger.LogAttrs(context.Background(), slog.LevelInfo, "tunnel_closed",
			slog.String("remote_addr", remote),
			slog.String("target", target),
			slog.String("repository", repository),
			slog.Int64("bytes_in", in),
			slog.Int64("bytes_out", out),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		)
	}()
}

func handleApiRequest(w http.ResponseWriter) {
	resp, err := http.Get("https://www.bing.com")
	if err != nil {
		logger.Error("api_example_fetch_failed", "err", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

// handleMetrics serves Prometheus-format counters. Unauthenticated by design
// — non-sensitive operational data, scraped by internal Prometheus or queried
// ad hoc. If exposure ever needs tightening, bind a separate listener on a
// non-public port and keep this off the public NLB target group.
func handleMetrics(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w,
		"# HELP oidc_gateway_connections_total CONNECT tunnels by outcome\n"+
			"# TYPE oidc_gateway_connections_total counter\n"+
			"oidc_gateway_connections_total{outcome=\"allowed\"} %d\n"+
			"oidc_gateway_connections_total{outcome=\"denied\"} %d\n"+
			"# HELP oidc_gateway_bytes_total Bytes proxied across tunnels by direction\n"+
			"# TYPE oidc_gateway_bytes_total counter\n"+
			"oidc_gateway_bytes_total{direction=\"in\"} %d\n"+
			"oidc_gateway_bytes_total{direction=\"out\"} %d\n"+
			"# HELP oidc_gateway_build_info Build metadata\n"+
			"# TYPE oidc_gateway_build_info gauge\n"+
			"oidc_gateway_build_info{version=%q} 1\n",
		connectionsAllowed.Load(),
		connectionsDenied.Load(),
		bytesIn.Load(),
		bytesOut.Load(),
		version,
	)
}

func isAllowedRepo(repository string) bool {
	parts := strings.SplitN(repository, "/", 2)
	if len(parts) != 2 {
		return false
	}
	repoName := parts[1]
	for _, allowed := range allowedRepos {
		if repoName == allowed {
			return true
		}
	}
	return false
}

func (gatewayContext *GatewayContext) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Unauthenticated health + metrics endpoints. /healthz is probed by the
	// NLB target group; /metrics is for Prometheus / ad-hoc inspection.
	switch req.RequestURI {
	case "/healthz":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
		return
	case "/metrics":
		handleMetrics(w)
		return
	}

	if req.Method != http.MethodConnect && req.RequestURI != "/apiExample" {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	// Validate the JWT came from GitHub. The JWT itself is never logged.
	oidcTokenString := string(req.Header.Get("Gateway-Authorization"))

	claims, err := validateTokenCameFromGitHub(oidcTokenString, gatewayContext)
	if err != nil {
		deny(w, req, "jwt_invalid", "err", err.Error())
		return
	}

	if claims["repository_owner"] != allowedOrg {
		extra := append(claimAttrs(claims), "expected_org", allowedOrg)
		deny(w, req, "wrong_org", extra...)
		return
	}

	if len(allowedRepos) > 0 {
		repo, ok := claims["repository"].(string)
		if !ok || !isAllowedRepo(repo) {
			deny(w, req, "wrong_repo", claimAttrs(claims)...)
			return
		}
	}

	if claims["aud"] != "api://ActionsOIDCGateway" {
		extra := append(claimAttrs(claims), "audience", safeStr(claims, "aud"))
		deny(w, req, "wrong_audience", extra...)
		return
	}

	// Allowed. Log the decision now; for CONNECT a tunnel_closed log will
	// follow once the tunnel finishes.
	connectionsAllowed.Add(1)
	allowAttrs := append([]any{"outcome", "allowed"}, requestAttrs(req)...)
	allowAttrs = append(allowAttrs, claimAttrs(claims)...)
	logger.Info("request_decision", allowAttrs...)

	if req.Method == http.MethodConnect {
		handleProxyRequest(w, req, claims)
	} else if req.RequestURI == "/apiExample" {
		handleApiRequest(w)
	}
}

func main() {
	logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	logger.Info("starting up", "addr", ":8000", "version", version)

	gatewayContext := &GatewayContext{jwksLastUpdate: time.Now()}

	server := http.Server{
		Addr:         ":8000",
		Handler:      gatewayContext,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	server.ListenAndServe()
}

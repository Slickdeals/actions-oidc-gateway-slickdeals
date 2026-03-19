package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const allowedOrg = "Slickdeals"

// Leave empty to allow all repos in the org.
// Populate to restrict to specific repos (just the repo name, not "org/repo").
var allowedRepos = []string{"sd-core"}

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
	httpClient     *http.Client
}

// Headers that should not be forwarded to the backend service
var sensitiveHeaders = map[string]bool{
	"Gateway-Authorization": true,
	"Authorization":         true,
	"Cookie":                true,
	"Set-Cookie":            true,
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
			fmt.Println(err)
			return nil, fmt.Errorf("Unable to get JWKS configuration")
		}

		jwksBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(err)
			return nil, fmt.Errorf("Unable to get JWKS configuration")
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

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleProxyRequest(w http.ResponseWriter, req *http.Request) {
	proxyConn, err := net.DialTimeout("tcp", req.Host, 5*time.Second)
	if err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusRequestTimeout), http.StatusRequestTimeout)
		return
	}

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		fmt.Println("Connection hijacking not supported")
		http.Error(w, http.StatusText(http.StatusExpectationFailed), http.StatusExpectationFailed)
		return
	}

	reqConn, _, err := hijacker.Hijack()
	if err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	go transfer(proxyConn, reqConn)
	go transfer(reqConn, proxyConn)
}

func handleApiRequest(w http.ResponseWriter, req *http.Request, gc *GatewayContext) {
	// Forward the request to sd-core service
	targetURL := "http://sd-core.internal:8080" + req.URL.Path
	if req.URL.RawQuery != "" {
		targetURL += "?" + req.URL.RawQuery
	}

	proxyReq, err := http.NewRequest(req.Method, targetURL, req.Body)
	if err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Copy headers from original request, excluding sensitive headers
	for key, values := range req.Header {
		if !sensitiveHeaders[key] {
			for _, value := range values {
				proxyReq.Header.Add(key, value)
			}
		}
	}

	resp, err := gc.httpClient.Do(proxyReq)
	if err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
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

// isApiRoute checks if the request path is an API route that should be proxied to sd-core
func isApiRoute(path string) bool {
	return strings.HasPrefix(path, "/api/")
}

func (gatewayContext *GatewayContext) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodConnect && !isApiRoute(req.URL.Path) {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	// Check that the OIDC token verifies as a valid token from GitHub
	//
	// This only means the OIDC token came from any GitHub Actions workflow,
	// we *must* check claims specific to our use case below
	oidcTokenString := string(req.Header.Get("Gateway-Authorization"))

	claims, err := validateTokenCameFromGitHub(oidcTokenString, gatewayContext)
	if err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// Token is valid, but we *must* check some claim specific to our use case
	//
	// For examples of other claims you could check, see:
	// https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#configuring-the-oidc-trust-with-the-cloud
	//
	// Here we check the same claims for all requests, but you could customize
	// the claims you check per handler below
	if claims["repository_owner"] != allowedOrg {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	if len(allowedRepos) > 0 {
		repo, ok := claims["repository"].(string)
		if !ok || !isAllowedRepo(repo) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
	}

	// You can customize the audience when you request an Actions OIDC token.
	//
	// This is a good idea to prevent a token being accidentally leaked by a
	// service from being used in another service.
	//
	// The example in the README.md requests this specific custom audience.
	if claims["aud"] != "api://ActionsOIDCGateway" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return

	}

	// Now that claims have been verified, we can service the request
	if req.Method == http.MethodConnect {
		handleProxyRequest(w, req)
	} else if isApiRoute(req.URL.Path) {
		handleApiRequest(w, req, gatewayContext)
	}
}

func main() {
	fmt.Println("starting up")

	gatewayContext := &GatewayContext{
		jwksLastUpdate: time.Now(),
		httpClient:     &http.Client{Timeout: 30 * time.Second},
	}

	server := http.Server{
		Addr:         ":8000",
		Handler:      gatewayContext,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	server.ListenAndServe()
}

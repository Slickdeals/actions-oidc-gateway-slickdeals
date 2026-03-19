package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func TestGetKeyForTokenMaker(t *testing.T) {
	// Create a JWKS for verifying tokens
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	pubKey := privateKey.Public().(*rsa.PublicKey)

	jwk := JWK{Kty: "RSA", Kid: "testKey", Alg: "RS256", Use: "sig"}
	jwk.N = base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	jwk.E = "AQAB"

	jwks := JWKS{Keys: []JWK{jwk}}

	jwksBytes, _ := json.Marshal(jwks)
	getKeyFunc := getKeyFromJwks(jwksBytes)

	// Test token referencing known key
	tokenClaims := jwt.MapClaims{"for": "testing"}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)

	token.Header["kid"] = "testKey"

	key, err := getKeyFunc(token)
	if err != nil {
		t.Error(err)
	}
	if key.(*rsa.PublicKey).N.Cmp(pubKey.N) != 0 {
		t.Error("public key does not match")
	}

	// Test token referencing unknown key
	token.Header["kid"] = "unknownKey"
	key, err = getKeyFunc(token)
	if err == nil {
		t.Error("Should fail when passed unknown key")
	}

	// Test token fails with any other signing key than RSA
	tokenHmac := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims)

	key, err = getKeyFunc(tokenHmac)
	if err == nil {
		t.Error("Should fail any signing algorithm other than RSA")
	}
}

func TestValidateTokenCameFromGitHub(t *testing.T) {
	// Create a JWKS for verifying tokens
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	pubKey := privateKey.Public().(*rsa.PublicKey)

	jwk := JWK{Kty: "RSA", Kid: "testKey", Alg: "RS256", Use: "sig"}
	jwk.N = base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	jwk.E = "AQAB"

	jwks := JWKS{Keys: []JWK{jwk}}
	jwksBytes, _ := json.Marshal(jwks)

	gatewayContext := &GatewayContext{jwksCache: jwksBytes, jwksLastUpdate: time.Now()}

	// Test token signed in the expected way
	tokenClaims := jwt.MapClaims{"for": "testing"}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	token.Header["kid"] = "testKey"

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}

	claims, err := validateTokenCameFromGitHub(signedToken, gatewayContext)

	if err != nil {
		t.Error(err)
	}
	if claims["for"] != "testing" {
		t.Error("Unable to find claims")
	}

	// Test signing with a unknown key is not allowed
	otherPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	signedToken, err = token.SignedString(otherPrivateKey)
	if err != nil {
		panic(err)
	}

	claims, err = validateTokenCameFromGitHub(signedToken, gatewayContext)
	if err == nil {
		t.Error("Should not validate token signed with other key")
	}

	// Test unsigned token is not allowed
	unsigendToken := jwt.NewWithClaims(jwt.SigningMethodNone, tokenClaims)
	unsigendToken.Header["kid"] = "testKey"

	noneToken, err := token.SignedString("none signing method allowed")

	claims, err = validateTokenCameFromGitHub(noneToken, gatewayContext)
	if err == nil {
		t.Error("Should not validate unsigned token")
	}
}

func TestIsAllowedRepo(t *testing.T) {
	originalRepos := allowedRepos
	defer func() { allowedRepos = originalRepos }()

	allowedRepos = []string{"my-app", "my-service"}

	if !isAllowedRepo("Slickdeals/my-app") {
		t.Error("Should allow repo in the allowlist")
	}
	if !isAllowedRepo("Slickdeals/my-service") {
		t.Error("Should allow repo in the allowlist")
	}
	if isAllowedRepo("Slickdeals/other-repo") {
		t.Error("Should reject repo not in the allowlist")
	}
	if isAllowedRepo("bad-format") {
		t.Error("Should reject repository without org/repo format")
	}
	if isAllowedRepo("") {
		t.Error("Should reject empty repository string")
	}
}

func TestIsApiRoute(t *testing.T) {
	if !isApiRoute("/api/test") {
		t.Error("Should accept paths starting with /api/")
	}
	if !isApiRoute("/api/v1/users") {
		t.Error("Should accept nested API paths")
	}
	if isApiRoute("/apiExample") {
		t.Error("Should reject paths not starting with /api/")
	}
	if isApiRoute("/other/api/test") {
		t.Error("Should reject paths where /api/ is not at the start")
	}
	if isApiRoute("/") {
		t.Error("Should reject root path")
	}
	if isApiRoute("") {
		t.Error("Should reject empty path")
	}
}

func newTestGatewayContext(t *testing.T) (*GatewayContext, *rsa.PrivateKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pubKey := privateKey.Public().(*rsa.PublicKey)
	jwk := JWK{Kty: "RSA", Kid: "testKey", Alg: "RS256", Use: "sig"}
	jwk.N = base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	jwk.E = "AQAB"

	jwks := JWKS{Keys: []JWK{jwk}}
	jwksBytes, _ := json.Marshal(jwks)

	gc := &GatewayContext{
		jwksCache:      jwksBytes,
		jwksLastUpdate: time.Now(),
		httpClient:     &http.Client{Timeout: 30 * time.Second},
	}
	return gc, privateKey
}

func signToken(t *testing.T, claims jwt.MapClaims, privateKey *rsa.PrivateKey) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "testKey"
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestServeHTTP_OrgAuthorization(t *testing.T) {
	gc, privateKey := newTestGatewayContext(t)
	originalRepos := allowedRepos
	defer func() { allowedRepos = originalRepos }()
	allowedRepos = []string{}

	t.Run("correct org is accepted", func(t *testing.T) {
		token := signToken(t, jwt.MapClaims{
			"repository_owner": "Slickdeals",
			"repository":       "Slickdeals/any-repo",
			"aud":              "api://ActionsOIDCGateway",
		}, privateKey)

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Gateway-Authorization", token)
		rr := httptest.NewRecorder()
		gc.ServeHTTP(rr, req)

		if rr.Code == http.StatusUnauthorized {
			t.Errorf("expected authorized, got %d", rr.Code)
		}
	})

	t.Run("wrong org is rejected", func(t *testing.T) {
		token := signToken(t, jwt.MapClaims{
			"repository_owner": "evil-org",
			"repository":       "evil-org/some-repo",
			"aud":              "api://ActionsOIDCGateway",
		}, privateKey)

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Gateway-Authorization", token)
		rr := httptest.NewRecorder()
		gc.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("missing org claim is rejected", func(t *testing.T) {
		token := signToken(t, jwt.MapClaims{
			"repository": "Slickdeals/some-repo",
			"aud":        "api://ActionsOIDCGateway",
		}, privateKey)

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Gateway-Authorization", token)
		rr := httptest.NewRecorder()
		gc.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rr.Code)
		}
	})
}

func TestServeHTTP_RepoAllowlist(t *testing.T) {
	gc, privateKey := newTestGatewayContext(t)
	originalRepos := allowedRepos
	defer func() { allowedRepos = originalRepos }()

	t.Run("empty allowlist permits any repo in org", func(t *testing.T) {
		allowedRepos = []string{}
		token := signToken(t, jwt.MapClaims{
			"repository_owner": "Slickdeals",
			"repository":       "Slickdeals/random-repo",
			"aud":              "api://ActionsOIDCGateway",
		}, privateKey)

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Gateway-Authorization", token)
		rr := httptest.NewRecorder()
		gc.ServeHTTP(rr, req)

		if rr.Code == http.StatusUnauthorized {
			t.Errorf("expected authorized with empty allowlist, got %d", rr.Code)
		}
	})

	t.Run("populated allowlist permits listed repo", func(t *testing.T) {
		allowedRepos = []string{"my-app", "my-service"}
		token := signToken(t, jwt.MapClaims{
			"repository_owner": "Slickdeals",
			"repository":       "Slickdeals/my-app",
			"aud":              "api://ActionsOIDCGateway",
		}, privateKey)

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Gateway-Authorization", token)
		rr := httptest.NewRecorder()
		gc.ServeHTTP(rr, req)

		if rr.Code == http.StatusUnauthorized {
			t.Errorf("expected authorized for allowed repo, got %d", rr.Code)
		}
	})

	t.Run("populated allowlist rejects unlisted repo", func(t *testing.T) {
		allowedRepos = []string{"my-app", "my-service"}
		token := signToken(t, jwt.MapClaims{
			"repository_owner": "Slickdeals",
			"repository":       "Slickdeals/other-repo",
			"aud":              "api://ActionsOIDCGateway",
		}, privateKey)

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Gateway-Authorization", token)
		rr := httptest.NewRecorder()
		gc.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for unlisted repo, got %d", rr.Code)
		}
	})

	t.Run("wrong audience is rejected", func(t *testing.T) {
		allowedRepos = []string{}
		token := signToken(t, jwt.MapClaims{
			"repository_owner": "Slickdeals",
			"repository":       "Slickdeals/my-app",
			"aud":              "wrong-audience",
		}, privateKey)

		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("Gateway-Authorization", token)
		rr := httptest.NewRecorder()
		gc.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for wrong audience, got %d", rr.Code)
		}
	})
}

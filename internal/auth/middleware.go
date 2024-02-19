package auth

import (
	"context"
	"net/http"

	routing "github.com/garaekz/ozzo-routing"
	"github.com/garaekz/ozzo-routing/auth"

	"github.com/garaekz/go-rest-api/internal/entity"
	"github.com/garaekz/go-rest-api/internal/errors"
	"github.com/golang-jwt/jwt/v5"
)

// JWTHandler returns a JWT-based authentication middleware.
func JWTHandler(verificationKey string) routing.Handler {
	return auth.JWT(verificationKey, auth.JWTOptions{TokenHandler: handleJWTToken})
}

// BearerHandler returns a Bearer token-based authentication middleware.
func BearerHandler(verificationKey string) routing.Handler {
	return auth.Bearer(func(c *routing.Context, _ string) (auth.Identity, error) {
		return handleBearerToken(c, verificationKey)
	})
}

// handleJWTToken stores the user identity in the request context so that it can be accessed elsewhere.
func handleJWTToken(c *routing.Context, token *jwt.Token) error {
	ctx := WithUser(
		c.Request.Context(),
		token.Claims.(jwt.MapClaims)["id"].(string),
		token.Claims.(jwt.MapClaims)["name"].(string),
	)
	c.Request = c.Request.WithContext(ctx)
	return nil
}

// handleBearerToken validates the bearer token and returns the user identity if the token is valid.
func handleBearerToken(_ *routing.Context, token string) (Identity, error) {
	if token == "secret" {
		return entity.User{}, nil
	}
	return nil, errors.Unauthorized("invalid token")
}

type contextKey int

const (
	userKey contextKey = iota
)

// WithUser returns a context that contains the user identity from the given JWT.
func WithUser(ctx context.Context, id, name string) context.Context {
	return context.WithValue(ctx, userKey, entity.User{ID: id, Name: name})
}

// CurrentUser returns the user identity from the given context.
// Nil is returned if no user identity is found in the context.
func CurrentUser(ctx context.Context) Identity {
	if user, ok := ctx.Value(userKey).(entity.User); ok {
		return user
	}
	return nil
}

// MockAuthHandler creates a mock authentication middleware for testing purpose.
// If the request contains an Authorization header whose value is "TEST", then
// it considers the user is authenticated as "Tester" whose ID is "100".
// It fails the authentication otherwise.
func MockAuthHandler(c *routing.Context) error {
	if c.Request.Header.Get("Authorization") != "TEST" {
		return errors.Unauthorized("")
	}
	ctx := WithUser(c.Request.Context(), "100", "Tester")
	c.Request = c.Request.WithContext(ctx)
	return nil
}

// MockAuthHeader returns an HTTP header that can pass the authentication check by MockAuthHandler.
func MockAuthHeader() http.Header {
	header := http.Header{}
	header.Add("Authorization", "TEST")
	return header
}

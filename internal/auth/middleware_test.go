package auth

import (
	"context"
	"net/http"
	"testing"

	"github.com/garaekz/go-rest-api/internal/test"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestCurrentUser(t *testing.T) {
	ctx := context.Background()
	assert.Nil(t, CurrentUser(ctx))
	ctx = WithUser(ctx, "100", "test")
	identity := CurrentUser(ctx)
	if assert.NotNil(t, identity) {
		assert.Equal(t, "100", identity.GetID())
		assert.Equal(t, "test", identity.GetName())
	}
}

func TestHandler(t *testing.T) {
	assert.NotNil(t, JWTHandler("test"))
}

func Test_handleToken(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	ctx, _ := test.MockRoutingContext(req)
	assert.Nil(t, CurrentUser(ctx.Request.Context()))

	err := handleJWTToken(ctx, &jwt.Token{
		Claims: jwt.MapClaims{
			"id":   "100",
			"name": "test",
		},
	})
	assert.Nil(t, err)
	identity := CurrentUser(ctx.Request.Context())
	if assert.NotNil(t, identity) {
		assert.Equal(t, "100", identity.GetID())
		assert.Equal(t, "test", identity.GetName())
	}
}

func TestMocks(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	ctx, _ := test.MockRoutingContext(req)
	assert.NotNil(t, MockAuthHandler(ctx))
	req.Header = MockAuthHeader()
	ctx, _ = test.MockRoutingContext(req)
	assert.Nil(t, MockAuthHandler(ctx))
	assert.NotNil(t, CurrentUser(ctx.Request.Context()))
}

func Test_handleBearerToken(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	ctx, _ := test.MockRoutingContext(req)
	assert.Nil(t, CurrentUser(ctx.Request.Context()))

	// Test valid token
	identity, err := handleBearerToken(ctx, "secret")
	assert.Nil(t, err)
	assert.NotNil(t, identity)

	// Test invalid token
	identity, err = handleBearerToken(ctx, "invalid")
	assert.NotNil(t, err)
	assert.Nil(t, identity)
}

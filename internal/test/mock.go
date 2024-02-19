package test

import (
	"net/http"
	"net/http/httptest"

	"github.com/garaekz/go-rest-api/internal/errors"
	"github.com/garaekz/go-rest-api/pkg/accesslog"
	"github.com/garaekz/go-rest-api/pkg/log"
	routing "github.com/garaekz/ozzo-routing"
	"github.com/garaekz/ozzo-routing/content"
	"github.com/garaekz/ozzo-routing/cors"
)

// MockRoutingContext creates a routing.Conext for testing handlers.
func MockRoutingContext(req *http.Request) (*routing.Context, *httptest.ResponseRecorder) {
	res := httptest.NewRecorder()
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	ctx := routing.NewContext(res, req)
	ctx.SetDataWriter(&content.JSONDataWriter{})
	return ctx, res
}

// MockRouter creates a routing.Router for testing APIs.
func MockRouter(logger log.Logger) *routing.Router {
	router := routing.New()
	router.Use(
		accesslog.Handler(logger),
		errors.Handler(logger),
		content.TypeNegotiator(content.JSON),
		cors.Handler(cors.AllowAll),
	)
	return router
}

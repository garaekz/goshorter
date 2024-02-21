package auth

import (
	"context"
	"net/http"
	"testing"

	"github.com/garaekz/goshorter/internal/errors"
	"github.com/garaekz/goshorter/internal/test"
	"github.com/garaekz/goshorter/pkg/log"
)

type mockService struct{}

func (mockService) Login(_ context.Context, username, _, password string) (string, error) {
	if username == "test" && password == "pass" {
		return "token-100", nil
	}
	return "", errors.Unauthorized("")
}

func (mockService) Register(_ context.Context, input RegisterRequest) (User, error) {
	if input.Username == "test" && input.Email == "test@test.io" && input.Password == "pass" {
		return User{}, nil
	}
	return User{}, errors.BadRequest("")
}

func (mockService) Verify(_ context.Context, userID, signature, expiration string) error {
	if userID == "test" && signature == "test" && expiration == "test" {
		return nil
	}
	return errors.BadRequest("")
}

func TestAPI(t *testing.T) {
	logger, _ := log.NewForTest()
	router := test.MockRouter(logger)
	RegisterHandlers(router.Group(""), router.Group(""), mockService{}, logger)

	tests := []test.APITestCase{
		{Name: "success", Method: "POST", URL: "/login", Body: `{"username":"test","password":"pass"}`, Header: nil, WantStatus: http.StatusOK, WantResponse: `{"data":{"token":"token-100"}, "message":"You have been successfully logged in.", "status":"success"}`},
		{Name: "bad credential", Method: "POST", URL: "/login", Body: `{"username":"test","password":"wrong pass"}`, Header: nil, WantStatus: http.StatusUnauthorized, WantResponse: ""},
		{Name: "bad json", Method: "POST", URL: "/login", Body: `"username":"test","password":"wrong pass"}`, Header: nil, WantStatus: http.StatusBadRequest, WantResponse: ""},
	}
	for _, tc := range tests {
		test.Endpoint(t, router, tc)
	}
}

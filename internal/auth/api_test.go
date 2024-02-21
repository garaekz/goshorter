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

func (mockService) Login(_ context.Context, credType, cred, password string) (string, error) {
	if credType == "username" && cred == "test" && password == "pass" {
		return "token-100", nil
	}

	if credType == "email" && cred == "test@test.io" && password == "pass" {
		return "token-100", nil
	}

	return "", errors.Unauthorized("Bad Login")
}

func (mockService) Register(_ context.Context, input RegisterRequest) (User, error) {
	if input.Email == "test@test.io" && input.Password == "pass" {
		return User{goodUser}, nil
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
		{Name: "success login username", Method: "POST", URL: "/login", Body: `{"username":"test","password":"pass"}`, Header: nil, WantStatus: http.StatusOK, WantResponse: `{"data":{"token":"token-100"}, "message":"You have been successfully logged in.", "status":"success"}`},
		{Name: "success login email", Method: "POST", URL: "/login", Body: `{"email":"test@test.io","password":"pass"}`, Header: nil, WantStatus: http.StatusOK, WantResponse: `{"data":{"token":"token-100"}, "message":"You have been successfully logged in.", "status":"success"}`},
		{Name: "bad credential", Method: "POST", URL: "/login", Body: `{"username":"test","password":"wrong pass"}`, Header: nil, WantStatus: http.StatusUnauthorized, WantResponse: ""},
		{Name: "bad login missing", Method: "POST", URL: "/login", Body: `{"password":"pass"}`, Header: nil, WantStatus: http.StatusBadRequest, WantResponse: `{"status":400,"message":"username or email is required"}`},
		{Name: "bad login extra", Method: "POST", URL: "/login", Body: `{"username":"username", "email":"email"}`, Header: nil, WantStatus: http.StatusBadRequest, WantResponse: `{"status":400,"message":"only one of username or email is allowed"}`},
		{Name: "bad json", Method: "POST", URL: "/login", Body: `"username":"test","password":"wrong pass"}`, Header: nil, WantStatus: http.StatusBadRequest, WantResponse: ""},
		{Name: "success register", Method: "POST", URL: "/register", Body: `{"first_name":"John","last_name":"Doe","username":"test","email":"test@test.io","password":"pass"}`, Header: nil, WantStatus: http.StatusCreated, WantResponse: `{"message":"Welcome John Doe!. An email has been sent to test@test.io. Please verify your account.","status":"success"}`},
		{Name: "bad register", Method: "POST", URL: "/register", Body: `{"first_name":"John","last_name":"Doe","username":"test"}`, Header: nil, WantStatus: http.StatusBadRequest, WantResponse: ""},
		{Name: "bad register service", Method: "POST", URL: "/register", Body: `{"first_name":"John","last_name":"Doe","username":"test","email":"bad email","password":"pass"}`, Header: nil, WantStatus: http.StatusBadRequest, WantResponse: ""},
		{Name: "bad register input", Method: "POST", URL: "/register", Body: `"first_name":"John","last_name":"Doe","username":"test","email":"bad email","password":"pass"}`, Header: nil, WantStatus: http.StatusBadRequest, WantResponse: ""},
		{Name: "success verify", Method: "GET", URL: "/verify?exp=test&id=test&sig=test", Body: "", Header: nil, WantStatus: http.StatusOK, WantResponse: ""},
		{Name: "bad verify", Method: "GET", URL: "/verify?exp=test&id=bad&sig=test", Body: "", Header: nil, WantStatus: http.StatusBadRequest, WantResponse: ""},
		{Name: "bad verify request", Method: "GET", URL: "/verify", Body: "", Header: nil, WantStatus: http.StatusBadRequest, WantResponse: ""},
	}
	for _, tc := range tests {
		test.Endpoint(t, router, tc)
	}
}

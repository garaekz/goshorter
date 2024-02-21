package auth

import (
	"net/http"

	"github.com/garaekz/goshorter/internal/errors"
	"github.com/garaekz/goshorter/pkg/log"
	routing "github.com/garaekz/ozzo-routing"
)

// RegisterHandlers registers handlers for different HTTP requests.
func RegisterHandlers(r *routing.RouteGroup, vr *routing.RouteGroup, service Service, logger log.Logger) {
	res := resource{service, logger}

	r.Post("/register", res.register)
	vr.Get("/verify", res.verify)
	r.Post("/login", login(service, logger))
}

type resource struct {
	service Service
	logger  log.Logger
}

// register returns a handler that handles user registration request.
func (r resource) register(c *routing.Context) error {
	var input RegisterRequest
	if err := c.Read(&input); err != nil {
		r.logger.With(c.Request.Context()).Info(err)
		return errors.BadRequest("")
	}
	user, err := r.service.Register(c.Request.Context(), input)
	if err != nil {
		return err
	}

	return c.WriteWithStatus(user, http.StatusCreated)
}

// verify returns a handler that handles user verification request.
func (r resource) verify(c *routing.Context) error {
	exp := c.Query("exp")
	id := c.Query("id")
	sig := c.Query("sig")

	if exp == "" || id == "" || sig == "" {
		return errors.BadRequest("invalid request")
	}

	return c.WriteWithStatus(nil, http.StatusOK)
}

// login returns a handler that handles user login request.
func login(service Service, logger log.Logger) routing.Handler {
	return func(c *routing.Context) error {
		var req struct {
			Username string `json:"username,omitempty"`
			Email    string `json:"email,omitempty"`
			Password string `json:"password"`
		}

		if err := c.Read(&req); err != nil {
			logger.With(c.Request.Context()).Errorf("invalid request: %v", err)
			return errors.BadRequest("")
		}

		if req.Username == "" && req.Email == "" {
			return errors.BadRequest("username or email is required")
		}

		if req.Username != "" && req.Email != "" {
			return errors.BadRequest("only one of username or email is allowed")
		}

		credential := req.Username
		credentialType := "username"
		if req.Email != "" {
			credential = req.Email
			credentialType = "email"
		}

		token, err := service.Login(c.Request.Context(), credential, credentialType, req.Password)
		if err != nil {
			return err
		}

		return c.Write(struct {
			Token string `json:"token"`
		}{token})
	}
}

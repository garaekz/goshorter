package auth

import (
	"net/http"

	"github.com/garaekz/goshorter/internal/errors"
	"github.com/garaekz/goshorter/pkg/log"
	routing "github.com/garaekz/ozzo-routing"
)

// RegisterHandlers registers handlers for different HTTP requests.
func RegisterHandlers(r *routing.RouteGroup, service Service, logger log.Logger) {
	res := resource{service, logger}

	r.Post("/register", res.register)
	// r.Post("/login", login(service, logger))
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

// login returns a handler that handles user login request.
// func login(service Service, logger log.Logger) routing.Handler {
// 	return func(c *routing.Context) error {
// 		var req struct {
// 			Username string `json:"username"`
// 			Password string `json:"password"`
// 		}

// 		if err := c.Read(&req); err != nil {
// 			logger.With(c.Request.Context()).Errorf("invalid request: %v", err)
// 			return errors.BadRequest("")
// 		}

// 		token, err := service.Login(c.Request.Context(), req.Username, req.Password)
// 		if err != nil {
// 			return err
// 		}
// 		return c.Write(struct {
// 			Token string `json:"token"`
// 		}{token})
// 	}
// }

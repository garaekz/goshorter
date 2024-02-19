package auth

import (
	"context"
	defaultErrors "errors"
	"time"

	"github.com/garaekz/goshorter/internal/entity"
	"github.com/garaekz/goshorter/internal/errors"
	"github.com/garaekz/goshorter/pkg/log"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/golang-jwt/jwt/v5"
)

// Service encapsulates the authentication logic.
type Service interface {
	Register(ctx context.Context, input RegisterRequest) (User, error)
	Login(ctx context.Context, username, password string) (string, error)
}

// User represents a user data.
type User struct {
	entity.User
}

// Identity represents an authenticated user identity.
type Identity interface {
	// GetID returns the user ID.
	GetID() string
	// GetEmail returns the user email.
	GetEmail() string
}

type service struct {
	repo            Repository
	signingKey      string
	tokenExpiration int
	logger          log.Logger
}

// NewService creates a new authentication service.
func NewService(repo Repository, signingKey string, tokenExpiration int, logger log.Logger) Service {
	return service{repo, signingKey, tokenExpiration, logger}
}

var errDuplicateEmail = defaultErrors.New(`pq: duplicate key value violates unique constraint "users_email_key"`)
var errDuplicateUsername = defaultErrors.New(`pq: duplicate key value violates unique constraint "users_username_key"`)

// RegisterRequest represents a user registration request.
type RegisterRequest struct {
	FirsName string `json:"first_name"`
	LastName string `json:"last_name"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// Validate validates the RegisterRequest fields.
func (m RegisterRequest) Validate() error {
	return validation.ValidateStruct(&m,
		validation.Field(&m.FirsName, validation.Required, validation.Length(0, 128)),
		validation.Field(&m.LastName, validation.Required, validation.Length(0, 128)),
		validation.Field(&m.Username, validation.Required, validation.Length(0, 128)),
		validation.Field(&m.Password, validation.Required, validation.Length(0, 128)),
		validation.Field(&m.Email, validation.Required, validation.Length(0, 128), is.Email),
	)
}

// Register creates a new user account.
func (s service) Register(ctx context.Context, req RegisterRequest) (User, error) {
	if err := req.Validate(); err != nil {
		return User{}, err
	}

	id := entity.GenerateID()
	password, err := entity.HashPassword(req.Password)
	if err != nil {
		return User{}, err
	}

	now := time.Now()
	user := entity.User{
		ID:        id,
		FirstName: req.FirsName,
		LastName:  req.LastName,
		Username:  req.Username,
		Password:  password,
		Email:     req.Email,
		CreatedAt: now,
		UpdatedAt: now,
	}

	err = s.repo.Register(ctx, user)
	if err != nil {
		if err.Error() == errDuplicateEmail.Error() {
			return User{}, errors.BadRequest("email already exists")
		}
		if err.Error() == errDuplicateUsername.Error() {
			return User{}, errors.BadRequest("username already exists")
		}

		return User{}, err
	}

	return User{user}, nil
}

// Login authenticates a user and generates a JWT token if authentication succeeds.
// Otherwise, an error is returned.
func (s service) Login(ctx context.Context, username, password string) (string, error) {
	if identity := s.authenticate(ctx, username, password); identity != nil {
		return s.generateJWT(identity)
	}
	return "", errors.Unauthorized("")
}

// authenticate authenticates a user using username and password.
// If username and password are correct, an identity is returned. Otherwise, nil is returned.
func (s service) authenticate(ctx context.Context, username, password string) Identity {
	logger := s.logger.With(ctx, "user", username)

	// TODO: the following authentication logic is only for demo purpose
	if username == "demo" && password == "pass" {
		logger.Infof("authentication successful")
		return entity.User{ID: "100", Email: "demo@test.io"}
	}

	logger.Infof("authentication failed")
	return nil
}

// generateJWT generates a JWT that encodes an identity.
func (s service) generateJWT(identity Identity) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":    identity.GetID(),
		"email": identity.GetEmail(),
		"exp":   time.Now().Add(time.Duration(s.tokenExpiration) * time.Hour).Unix(),
	}).SignedString([]byte(s.signingKey))
}

package auth

import (
	"context"
	defaultErrors "errors"
	"time"

	"github.com/garaekz/goshorter/internal/entity"
	"github.com/garaekz/goshorter/internal/errors"
	"github.com/garaekz/goshorter/pkg/log"
	"github.com/garaekz/goshorter/pkg/url"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/golang-jwt/jwt/v5"
)

// Service encapsulates the authentication logic.
type Service interface {
	Register(ctx context.Context, input RegisterRequest) (User, error)
	Login(ctx context.Context, username, credType, password string) (string, error)
	Verify(ctx context.Context, userID, signature, expiration string) error
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
	repo   Repository
	logger log.Logger
	cfg    ServiceConfig
}

// ServiceConfig represents the configuration settings for the authentication service.
type ServiceConfig struct {
	SigningKey      string
	SecretKey       string
	TokenExpiration int
	BaseURL         string
	ServerPort      int
	Mailer          Mailer
}

// Mailer represents an email service.
type Mailer interface {
	SendValidateAccountMail(ctx context.Context, email, userID, baseURL, secretKey string, serverPort int) error
}

// NewService creates a new authentication service.
func NewService(repo Repository, logger log.Logger, cfg ServiceConfig) Service {
	return service{repo, logger, cfg}
}

var errDuplicateEmail = defaultErrors.New(`pq: duplicate key value violates unique constraint "users_email_key"`)
var errDuplicateUsername = defaultErrors.New(`pq: duplicate key value violates unique constraint "users_username_key"`)

// RegisterRequest represents a user registration request.
type RegisterRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Email     string `json:"email"`
}

// Validate validates the RegisterRequest fields.
func (m RegisterRequest) Validate() error {
	return validation.ValidateStruct(&m,
		validation.Field(&m.FirstName, validation.Required, validation.Length(0, 128)),
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

	password, err := entity.HashPassword(req.Password)
	if err != nil {
		return User{}, err
	}

	now := time.Now()
	user := entity.User{
		ID:        entity.GenerateID(),
		FirstName: req.FirstName,
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

	err = s.cfg.Mailer.SendValidateAccountMail(ctx, user.Email, user.ID, s.cfg.BaseURL, s.cfg.SecretKey, s.cfg.ServerPort)
	if err != nil {
		return User{}, err
	}

	return User{user}, nil
}

func (s service) Verify(ctx context.Context, userID, signature, expiration string) error {
	if valid := url.VerifySignature("/verify", signature, expiration, s.cfg.SecretKey, map[string]string{"id": userID}); !valid {
		return errors.BadRequest("invalid verification link")
	}

	user, err := s.repo.FindUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if user.VerifiedAt != nil {
		return errors.BadRequest("user already verified")
	}

	now := time.Now()
	user.VerifiedAt = &now

	err = s.repo.Update(ctx, *user)
	if err != nil {
		return err
	}

	return nil
}

// Login authenticates a user and generates a JWT token if authentication succeeds.
// Otherwise, an error is returned.
func (s service) Login(ctx context.Context, username, credType, password string) (string, error) {
	if identity := s.authenticate(ctx, username, credType, password); identity != nil {
		return s.generateJWT(identity)
	}
	return "", errors.Unauthorized("Invalid login credentials. Please try again.")
}

// authenticate authenticates a user using username/email and password.
// If username/email and password are correct, an identity is returned. Otherwise, nil is returned.
func (s service) authenticate(ctx context.Context, credential, credType, password string) Identity {
	logger := s.logger.With(ctx, "user", credential)

	if credType != "username" && credType != "email" {
		logger.Errorf("invalid credential type: %s", credType)
		return nil
	}
	var user *entity.User
	if credType == "email" {
		if err := validation.Validate(credential, is.Email); err != nil {
			logger.Errorf("invalid email: %s", credential)
			return nil
		}

		userData, err := s.repo.FindVerifiedUserByEmail(ctx, credential)
		user = userData
		if err != nil {
			logger.Errorf("failed to find user by email: %v", err)
			return nil
		}
	} else {
		userData, err := s.repo.FindVerifiedUserByUsername(ctx, credential)
		if err != nil {
			logger.Errorf("failed to find user by username: %v", err)
			return nil
		}
		user = userData
	}

	validPass := entity.CheckPasswordHash(password, user.Password)
	if validPass {
		return user
	}

	logger.Infof("authentication failed")
	return nil
}

// generateJWT generates a JWT that encodes an identity.
func (s service) generateJWT(identity Identity) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":    identity.GetID(),
		"email": identity.GetEmail(),
		"exp":   time.Now().Add(time.Duration(s.cfg.TokenExpiration) * time.Hour).Unix(),
	}).SignedString([]byte(s.cfg.SigningKey))
}

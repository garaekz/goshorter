package auth

import (
	"context"
	"testing"
	"time"

	"github.com/garaekz/goshorter/internal/entity"
	"github.com/garaekz/goshorter/internal/errors"
	"github.com/garaekz/goshorter/pkg/log"
	"github.com/garaekz/goshorter/pkg/url"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/crypto/bcrypt"
)

// setupNewService is a helper function to create a new service instance for testing.
func setupNewService() (*service, *observer.ObservedLogs) {
	repo := &mockRepo{}
	logger, watcher := log.NewForTest()
	cfg := ServiceConfig{
		Mailer:          &mockMailer{},
		SigningKey:      "signingKey",
		SecretKey:       "secretKey",
		TokenExpiration: 1,
	}

	return &service{
		repo:   repo,
		logger: logger,
		cfg:    cfg,
	}, watcher
}

func TestNewService(t *testing.T) {
	repo := &mockRepo{}
	logger, _ := log.NewForTest()
	cfg := ServiceConfig{
		Mailer: &mockMailer{},
	}

	s := NewService(repo, logger, cfg)

	assert.NotNil(t, s)
}

func TestRegister(t *testing.T) {
	ctx := context.Background()
	s, _ := setupNewService()

	req := RegisterRequest{
		LastName: "test",
		Username: "test",
		Email:    "test@test.io",
		Password: "pass",
	}
	// Validation error
	user, err := s.Register(ctx, req)
	assert.NotNil(t, err)
	assert.Empty(t, user.ID)

	req.FirstName = "test"

	// Duplicate email
	req.Email = "dupe@test.io"
	user, err = s.Register(ctx, req)
	assert.NotNil(t, err)
	assert.Empty(t, user.ID)
	assert.Equal(t, errors.BadRequest("email already exists"), err)

	// Duplicate username
	req.Username = "dupe"
	req.Email = "test@test.io"
	user, err = s.Register(ctx, req)
	assert.NotNil(t, err)
	assert.Empty(t, user.ID)
	assert.Equal(t, errors.BadRequest("username already exists"), err)

	// Error sending email
	req.Email = "fail@test.io"
	user, err = s.Register(ctx, req)
	assert.NotNil(t, err)
	assert.Empty(t, user)

	// Success register
	req.Username = "success"
	req.Email = "success@test.io"
	user, err = s.Register(ctx, req)
	assert.Nil(t, err)
	assert.NotEmpty(t, user.ID)
	assert.Equal(t, "success", user.Username)
	assert.Equal(t, "success@test.io", user.Email)
	assert.Nil(t, bcrypt.CompareHashAndPassword([]byte(user.Password), []byte("pass")))
	assert.NotEmpty(t, user.CreatedAt)
	assert.NotEmpty(t, user.UpdatedAt)

}

func TestVerify(t *testing.T) {
	ctx := context.Background()
	s, _ := setupNewService()

	// Invalid token
	err := s.Verify(ctx, goodUser.ID, "invalid", "0")
	assert.NotNil(t, err)
	assert.Equal(t, errors.BadRequest("invalid verification link"), err)

	// User not found
	signature := url.GenerateSignature(s.cfg.SecretKey, "/verify", map[string]string{"id": "badId"}, "")

	err = s.Verify(ctx, "badId", signature, "")
	assert.NotNil(t, err)

	// User already verified
	signature = url.GenerateSignature(s.cfg.SecretKey, "/verify", map[string]string{"id": goodUser.ID}, "")
	err = s.Verify(ctx, goodUser.ID, signature, "")
	assert.NotNil(t, err)
	assert.Equal(t, errors.BadRequest("user already verified"), err)

	// Error updating user
	signature = url.GenerateSignature(s.cfg.SecretKey, "/verify", map[string]string{"id": failUser.ID}, "")
	err = s.Verify(ctx, failUser.ID, signature, "")
	assert.NotNil(t, err)

	// Success
	signature = url.GenerateSignature(s.cfg.SecretKey, "/verify", map[string]string{"id": unverifiedUser.ID}, "")
	err = s.Verify(ctx, unverifiedUser.ID, signature, "")
	assert.Nil(t, err)
	assert.NotNil(t, unverifiedUser.VerifiedAt)

}

func Test_authenticate(t *testing.T) {
	ctx := context.Background()
	s, watcher := setupNewService()

	// Invalid credential type
	user := s.authenticate(ctx, "invalid", "test", "pass")
	assert.Nil(t, user)
	assert.Contains(t, watcher.All()[0].Message, "invalid credential type: invalid")

	// Invalid email format
	user = s.authenticate(ctx, "email", "invalid", "pass")
	assert.Nil(t, user)
	assert.Contains(t, watcher.All()[1].Message, "invalid email: invalid")

	// Invalid email
	user = s.authenticate(ctx, "email", "invalid@test.io", "pass")
	assert.Nil(t, user)
	assert.Contains(t, watcher.All()[2].Message, "failed to find user by email: ")

	// Invalid username
	user = s.authenticate(ctx, "username", "invalid", "pass")
	assert.Nil(t, user)
	assert.Contains(t, watcher.All()[3].Message, "failed to find user by username: ")

	// Password mismatch
	user = s.authenticate(ctx, "username", goodUser.Username, "invalid")
	assert.Nil(t, user)
	assert.Contains(t, watcher.All()[4].Message, "authentication failed")
}

func TestService_GenerateJWT(t *testing.T) {
	mockIdentity := new(MockIdentity)
	mockIdentity.On("GetID").Return("123")
	mockIdentity.On("GetEmail").Return("user@example.com")
	s, _ := setupNewService()

	tokenString, err := s.generateJWT(mockIdentity)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			t.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.cfg.SigningKey), nil
	})

	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok)

	assert.Equal(t, "123", claims["id"])
	assert.Equal(t, "user@example.com", claims["email"])

	// Verificar expiración
	expiration, ok := claims["exp"].(float64)
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(time.Duration(s.cfg.TokenExpiration)*time.Hour), time.Unix(int64(expiration), 0), 5*time.Second)
}

func TestLogin(t *testing.T) {
	ctx := context.Background()
	s, _ := setupNewService()

	// Success
	token, err := s.Login(ctx, "username", "test", "pass")
	assert.Nil(t, err)
	assert.NotEmpty(t, token)
}

type MockIdentity struct {
	mock.Mock
}

func (m *MockIdentity) GetID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockIdentity) GetEmail() string {
	args := m.Called()
	return args.String(0)
}

type mockMailer struct{}

func (*mockMailer) SendValidateAccountMail(to, _, _, _ string, _ int) error {
	if to == "fail@test.io" {
		return errors.InternalServerError("error sending email")
	}
	return nil
}

var testConfig = &ServiceConfig{
	SecretKey: "SecretKey",
	Mailer:    &mockMailer{},
}

type mockRepo struct {
	items []entity.User
}

var now = time.Now()
var goodPass, _ = entity.HashPassword("pass")
var goodUser = entity.User{
	ID:         "test",
	FirstName:  "John",
	LastName:   "Doe",
	Username:   "test",
	Email:      "test@test.io",
	Password:   goodPass,
	VerifiedAt: &now,
}
var failUser = entity.User{
	ID: "fail",
}

var unverifiedUser = entity.User{
	ID:        "unverified",
	FirstName: "John",
	LastName:  "Doe",
	Username:  "unverified",
	Email:     "unv@test.io",
	Password:  "pass",
}

func (*mockRepo) Register(_ context.Context, user entity.User) error {
	if user.Email == "dupe@test.io" {
		return errDuplicateEmail
	}

	if user.Username == "dupe" {
		return errDuplicateUsername
	}

	return nil
}

func (*mockRepo) FindUserByID(_ context.Context, id string) (*entity.User, error) {
	if id == goodUser.ID {
		return &goodUser, nil
	}

	if id == failUser.ID {
		return &failUser, nil
	}

	if id == unverifiedUser.ID {
		return &unverifiedUser, nil
	}

	return &entity.User{}, errors.NotFound("user not found")
}

func (*mockRepo) FindVerifiedUserByEmail(_ context.Context, email string) (*entity.User, error) {
	if email == goodUser.Email {
		return &goodUser, nil
	}
	return &entity.User{}, errors.NotFound("user not found")
}

func (*mockRepo) Update(_ context.Context, user entity.User) error {
	if user.ID == failUser.ID {
		return errors.InternalServerError("error updating user")
	}

	if user.ID == unverifiedUser.ID {
		unverifiedUser.VerifiedAt = user.VerifiedAt
	}

	return nil
}

func (*mockRepo) FindVerifiedUserByUsername(_ context.Context, username string) (*entity.User, error) {
	if username == goodUser.Username {
		return &goodUser, nil
	}
	return &entity.User{}, errors.NotFound("user not found")
}

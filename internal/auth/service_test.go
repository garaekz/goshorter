package auth

import (
	"context"
	"testing"
	"time"

	"github.com/garaekz/goshorter/internal/entity"
	"github.com/garaekz/goshorter/internal/errors"
	"github.com/garaekz/goshorter/pkg/log"
	"github.com/garaekz/goshorter/pkg/url"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

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
	repo := &mockRepo{}

	// Create a service instance
	s := service{
		repo: repo,
		cfg:  *testConfig,
	}

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
	repo := &mockRepo{}

	// Create a service instance
	s := service{
		repo: repo,
		cfg:  *testConfig,
	}

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
var goodUser = entity.User{
	ID:         "test",
	FirstName:  "John",
	LastName:   "Doe",
	Username:   "test",
	Email:      "test@test.io",
	Password:   "pass",
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
	return &entity.User{}, nil
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
	return &entity.User{}, nil
}

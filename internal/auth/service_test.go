package auth

import (
	"context"
	"testing"

	"github.com/garaekz/goshorter/internal/entity"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

type mockMailer struct{}

func (*mockMailer) SendValidateAccountMail(_ context.Context, _, _, _, _ string, _ int) error {
	return nil
}

var testConfig = &ServiceConfig{
	Mailer: &mockMailer{},
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
		FirstName: "test",
		LastName:  "test",
		Username:  "test",
		Email:     "test@test.io",
		Password:  "pass",
	}
	// successful creation
	user, err := s.Register(ctx, req)
	assert.Nil(t, err)
	assert.NotEmpty(t, user.ID)
	assert.Equal(t, "test", user.Username)
	assert.Equal(t, "test@test.io", user.Email)
	assert.Nil(t, bcrypt.CompareHashAndPassword([]byte(user.Password), []byte("pass")))
	assert.NotEmpty(t, user.CreatedAt)
	assert.NotEmpty(t, user.UpdatedAt)
}

type mockRepo struct {
	items []entity.User
}

var goodUser = entity.User{
	ID:        "test",
	FirstName: "John",
	LastName:  "Doe",
	Username:  "test",
	Email:     "test@test.io",
	Password:  "pass",
}

func (*mockRepo) Register(_ context.Context, _ entity.User) error {
	return nil
}

func (*mockRepo) FindUserByID(_ context.Context, id string) (*entity.User, error) {
	if id == goodUser.ID {
		return &goodUser, nil
	}

	return &entity.User{}, nil
}

func (*mockRepo) FindVerifiedUserByEmail(_ context.Context, email string) (*entity.User, error) {
	if email == goodUser.Email {
		return &goodUser, nil
	}
	return &entity.User{}, nil
}

func (*mockRepo) Update(_ context.Context, _ entity.User) error {
	return nil
}

func (*mockRepo) FindVerifiedUserByUsername(_ context.Context, username string) (*entity.User, error) {
	if username == goodUser.Username {
		return &goodUser, nil
	}
	return &entity.User{}, nil
}

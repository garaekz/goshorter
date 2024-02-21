package auth

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/garaekz/goshorter/internal/entity"
	"github.com/garaekz/goshorter/internal/test"
	"github.com/garaekz/goshorter/pkg/log"
	"github.com/stretchr/testify/assert"
)

func TestRepository(t *testing.T) {
	logger, _ := log.NewForTest()
	db := test.DB(t)
	test.ResetTables(t, db, "users")
	repo := NewRepository(db, logger)

	ctx := context.Background()

	defaultUser := entity.User{
		ID:        "test1",
		Username:  "user1",
		Email:     "testing1@test.io",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	// register
	err := repo.Register(ctx, defaultUser)
	assert.Nil(t, err)
	assert.NotEmpty(t, defaultUser.ID)
	assert.Equal(t, "test1", defaultUser.ID)
	assert.Equal(t, "user1", defaultUser.Username)

	// FindUserByID
	user, err := repo.FindUserByID(ctx, "test1")
	assert.Nil(t, err)
	assert.Equal(t, "user1", user.Username)

	// update
	err = repo.Update(ctx, entity.User{
		ID:        "test1",
		Username:  "user1 updated",
		Email:     "testing1@test.io",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	assert.Nil(t, err)
	user, _ = repo.FindUserByID(ctx, "test1")
	assert.Equal(t, "user1 updated", user.Username)

	// FindVerifiedUserByEmail
	user, err = repo.FindVerifiedUserByEmail(ctx, "test1@test.io")
	assert.NotNil(t, user)
	assert.Equal(t, sql.ErrNoRows, err)

	now := time.Now()
	err = repo.Update(ctx, entity.User{
		ID:         "test1",
		Username:   "user1 updated",
		Email:      "testing1@test.io",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		VerifiedAt: &now,
	})

	// FindVerifiedUserByUsername
	user, err = repo.FindVerifiedUserByUsername(ctx, "user1 updated")
	assert.NotNil(t, user)
	assert.Nil(t, err)
}

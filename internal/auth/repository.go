package auth

import (
	"context"

	"github.com/garaekz/goshorter/internal/entity"
	"github.com/garaekz/goshorter/pkg/dbcontext"
	"github.com/garaekz/goshorter/pkg/log"
	dbx "github.com/go-ozzo/ozzo-dbx"
)

// Repository encapsulates the logic to access albums from the data source.
type Repository interface {
	// Register saves a new user in the storage
	Register(ctx context.Context, user entity.User) error
	// FindUserByID returns the user with the given ID
	FindUserByID(ctx context.Context, id string) (*entity.User, error)
	// FindVerifiedUserByEmail returns the user with the given email when verified_at is not null
	FindVerifiedUserByEmail(ctx context.Context, email string) (*entity.User, error)
	// FindVerifiedUserByUsername returns the user with the given username when verified_at is not null
	FindVerifiedUserByUsername(ctx context.Context, username string) (*entity.User, error)
	// Update updates the user in the storage
	Update(ctx context.Context, user entity.User) error
}

// repository persists albums in database
type repository struct {
	db     *dbcontext.DB
	logger log.Logger
}

// NewRepository creates a new album repository
func NewRepository(db *dbcontext.DB, logger log.Logger) Repository {
	return repository{db, logger}
}

func (r repository) Register(ctx context.Context, user entity.User) error {
	return r.db.With(ctx).Model(&user).Insert()
}

func (r repository) FindUserByID(ctx context.Context, id string) (*entity.User, error) {
	var user entity.User
	err := r.db.With(ctx).Select().From("users").Where(dbx.HashExp{"id": id}).One(&user)
	return &user, err
}

func (r repository) FindVerifiedUserByEmail(ctx context.Context, credential string) (*entity.User, error) {
	var user entity.User
	err := r.db.With(ctx).Select().From("users").Where(dbx.HashExp{"email": credential}).AndWhere(dbx.Not(dbx.HashExp{"verified_at": nil})).One(&user)
	return &user, err
}

func (r repository) FindVerifiedUserByUsername(ctx context.Context, credential string) (*entity.User, error) {
	var user entity.User
	err := r.db.With(ctx).Select().From("users").Where(dbx.HashExp{"username": credential}).AndWhere(dbx.Not(dbx.HashExp{"verified_at": nil})).One(&user)
	return &user, err
}

func (r repository) Update(ctx context.Context, user entity.User) error {
	return r.db.With(ctx).Model(&user).Update()
}

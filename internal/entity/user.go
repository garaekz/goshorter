package entity

import (
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User represents a user.
type User struct {
	ID         string
	FirstName  string
	LastName   string
	Email      string
	Username   string
	Password   string
	VerifiedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// TableName represents the table name
func (User) TableName() string {
	return "users"
}

// GetID returns the user ID.
func (u User) GetID() string {
	return u.ID
}

// GetFullName returns the user full name.
func (u User) GetFullName() string {
	return fmt.Sprintf("%s %s", u.FirstName, u.LastName)
}

// GetEmail returns the user email.
func (u User) GetEmail() string {
	return u.Email
}

// HashPassword hashes the provided password using bcrypt.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash compares the provided password with his hashed version.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

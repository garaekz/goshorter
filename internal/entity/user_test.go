package entity

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestTableName(t *testing.T) {
	expected := "users"
	user := User{}
	tableName := user.TableName()
	if tableName != expected {
		t.Errorf("Unexpected table name. Expected: %s, Got: %s", expected, tableName)
	}
}

func TestGetID(t *testing.T) {
	expected := "123"
	user := User{ID: expected}
	id := user.GetID()
	if id != expected {
		t.Errorf("Unexpected user ID. Expected: %s, Got: %s", expected, id)
	}
}

func TestGetFullName(t *testing.T) {
	expected := "John Doe"
	user := User{FirstName: "John", LastName: "Doe"}
	fullName := user.GetFullName()
	if fullName != expected {
		t.Errorf("Unexpected user full name. Expected: %s, Got: %s", expected, fullName)
	}
}

func TestGetEmail(t *testing.T) {
	expected := "test@test.io"
	user := User{Email: expected}
	email := user.GetEmail()
	if email != expected {
		t.Errorf("Unexpected user email. Expected: %s, Got: %s", expected, email)
	}
}

func TestHashPassword(t *testing.T) {
	password := "password123"
	hashedPassword, err := HashPassword(password)
	if err != nil {
		t.Errorf("Error hashing password: %v", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		t.Errorf("Hashed password does not match original password")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "password123"
	hashedPassword, err := HashPassword(password)
	if err != nil {
		t.Errorf("Error hashing password: %v", err)
	}

	match := CheckPasswordHash(password, hashedPassword)
	if !match {
		t.Errorf("Hashed password does not match original password")
	}
}

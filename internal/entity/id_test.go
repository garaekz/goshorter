package entity

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestGenerateID(t *testing.T) {
	id := GenerateID()
	_, err := uuid.Parse(id)
	assert.NoError(t, err)
}

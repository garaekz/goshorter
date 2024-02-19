package config

import (
	"os"
	"testing"

	"github.com/garaekz/go-rest-api/pkg/log"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "valid configuration",
			cfg:     Config{DSN: "some-dsn", JWTSigningKey: "some-key"},
			wantErr: false,
		},
		{
			name:    "missing DSN",
			cfg:     Config{JWTSigningKey: "some-key"},
			wantErr: true,
		},
		{
			name:    "missing JWTSigningKey",
			cfg:     Config{DSN: "some-dsn"},
			wantErr: true,
		},
		{
			name:    "both fields missing",
			cfg:     Config{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

const testConfigContent = `
server_port: 8080
jwt_expiration: 24
dsn: "your-dsn-here"
jwt_signing_key: "your-jwt-key-here"
`
const testConfigContentInvalid = `
serverPort: "no es un número"
`

func TestLoad(t *testing.T) {
	// Setup del sistema de archivos en memoria usando Afero, si es necesario
	logger, _ := log.NewForTest()
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}
	fileName := "test.yaml"
	_ = afero.WriteFile(fs, fileName, []byte(testConfigContent), 0644)

	t.Run("valid config file", func(t *testing.T) {
		cfg, err := Load(fileName, logger, afs)
		require.NoError(t, err)
		assert.Equal(t, 8080, cfg.ServerPort)
		assert.Equal(t, 24, cfg.JWTExpiration)
	})

	t.Run("invalid config file", func(t *testing.T) {
		invalidFileName := "invalidConfig.yaml"
		_ = afero.WriteFile(fs, invalidFileName, []byte(testConfigContentInvalid), 0644)

		_, err := Load(invalidFileName, logger, afs)
		require.Error(t, err)
	})

	t.Run("file does not exist", func(t *testing.T) {
		_, err := Load("nonexistent.yaml", logger, afs)
		require.Error(t, err)
	})

	t.Run("yaml unmarshal error", func(t *testing.T) {
		invalidYAMLContent := ":\n"
		fileName := "invalidConfig.yaml"
		_ = afero.WriteFile(fs, fileName, []byte(invalidYAMLContent), 0644)
		_, err := Load(fileName, logger, afs)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "yaml")
	})
}

func TestOSFileSystem_ReadFile(t *testing.T) {
	logger, _ := log.NewForTest()
	tmpfile, err := os.CreateTemp("", "example")
	if err != nil {
		logger.Error(err)
	}
	defer os.Remove(tmpfile.Name())

	content := []byte("hello world")
	if _, err := tmpfile.Write(content); err != nil {
		tmpErr := tmpfile.Close()
		if tmpErr != nil {
			logger.Error(tmpErr)
		}
		logger.Error(err)
	}
	if err := tmpfile.Close(); err != nil {
		logger.Error(err)
	}

	fs := OSFileSystem{}
	data, err := fs.ReadFile(tmpfile.Name())
	require.NoError(t, err)
	assert.Equal(t, content, data)
}

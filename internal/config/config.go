package config

import (
	"os"

	"github.com/garaekz/goshorter/pkg/log"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/qiangxue/go-env"
	"gopkg.in/yaml.v2"
)

const (
	defaultServerPort         = 8080
	defaultJWTExpirationHours = 72
)

// OSFileSystem represents a real OS file system.
type OSFileSystem struct{}

// FileSystem represents a file system.
type FileSystem interface {
	ReadFile(name string) ([]byte, error)
}

// Config represents an application configuration.
type Config struct {
	BaseURL string `yaml:"base_url" env:"BASE_URL"`
	// the server port. Defaults to 8080
	ServerPort int `yaml:"server_port" env:"SERVER_PORT"`
	// the data source name (DSN) for connecting to the database. required.
	DSN string `yaml:"dsn" env:"DSN,secret"`
	// JWT signing key. required.
	JWTSigningKey string `yaml:"jwt_signing_key" env:"JWT_SIGNING_KEY,secret"`
	// JWT expiration in hours. Defaults to 72 hours (3 days)
	JWTExpiration int `yaml:"jwt_expiration" env:"JWT_EXPIRATION"`
	// SMTPConfig represents the SMTP configuration.
	SMTPConfig SMTPConfig `yaml:"smtp_config" env:"SMTP"`
	// SecretKey is used to encrypt and decrypt data
	SecretKey string `yaml:"secret_key" env:"SECRET_KEY,secret"`
}

// SMTPConfig represents the SMTP configuration.
type SMTPConfig struct {
	Host      string `yaml:"host" env:"SMTP_HOST"`
	Port      int    `yaml:"port" env:"SMTP_PORT"`
	Username  string `yaml:"username" env:"SMTP_USERNAME"`
	Password  string `yaml:"password" env:"SMTP_PASSWORD,secret"`
	FromEmail string `yaml:"from_email" env:"SMTP_FROM_EMAIL"`
	FromName  string `yaml:"from_name" env:"SMTP_FROM_NAME"`
}

// Validate validates the application configuration.
func (c Config) Validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.DSN, validation.Required),
		validation.Field(&c.JWTSigningKey, validation.Required),
	)
}

// Load returns an application configuration which is populated from the given configuration file and environment variables.
func Load(file string, logger log.Logger, fs FileSystem) (*Config, error) {
	// default config
	c := Config{
		ServerPort:    defaultServerPort,
		JWTExpiration: defaultJWTExpirationHours,
	}

	// load from YAML config file
	bytes, err := fs.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if err = yaml.Unmarshal(bytes, &c); err != nil {
		return nil, err
	}

	// load from environment variables prefixed with "APP_"
	if err = env.New("APP_", logger.Infof).Load(&c); err != nil {
		return nil, err
	}

	// validation
	if err = c.Validate(); err != nil {
		return nil, err
	}

	return &c, err
}

// ReadFile reads the file from the real OS file system.
func (OSFileSystem) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

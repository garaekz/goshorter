package sendmail

import (
	"net/smtp"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockSMTPSender struct {
	mock.Mock
}

type MockTemplateParser struct {
	mock.Mock
}

type MockTemplateMailer struct {
	mock.Mock
}

func (m *MockSMTPSender) SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	args := m.Called(addr, a, from, to, msg)
	return args.Error(0)
}

func (m *MockTemplateParser) ParseAndExecute(templateName string, data interface{}) (string, error) {
	args := m.Called(templateName, data)
	return args.String(0), args.Error(1)
}

func (m *MockTemplateMailer) SendTemplateEmail(to, subject, templatePath string, data interface{}) error {
	args := m.Called(to, subject, templatePath, data)
	return args.Error(0)
}

func NewMailer() *Mailer {
	smtpSender := new(MockSMTPSender)
	smtpSender.On("SendMail", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	templateParser := new(MockTemplateParser)
	templateParser.On("ParseAndExecute", mock.Anything, mock.Anything).Return("template", nil)

	mailer := Mailer{
		Host:      "smtp.example.com",
		Port:      587,
		FromEmail: "no-reply@example.com",
		FromName:  "Example",
		Sender:    smtpSender,
		Templates: templateParser,
	}

	return &mailer
}

func TestMailer_SendTemplateEmail(t *testing.T) {
	mailer := NewMailer()
	err := mailer.SendTemplateEmail("to@example.com", "Subject", "template.html", nil)

	assert.NoError(t, err)
}

func TestMailer_SendValidateAccountMail(t *testing.T) {
	mailer := NewMailer()
	err := mailer.SendValidateAccountMail("t@t.io", "test", "https://example.com", "secret", 80)

	assert.NoError(t, err)
}

func Test_getPortSuffix(t *testing.T) {
	assert.Equal(t, ":587", getPortSuffix(587))
	assert.Equal(t, ":465", getPortSuffix(465))
	assert.Equal(t, ":25", getPortSuffix(25))
	assert.Equal(t, "", getPortSuffix(80))
	assert.Equal(t, "", getPortSuffix(443))
}

func TestTemplateAdapter_ParseAndExecute(t *testing.T) {
	adapter := TemplateAdapter{}
	t.Run("successful parse and execute", func(t *testing.T) {
		templateName := filepath.Join("../../templates", "test.html")

		data := map[string]string{"Name": "World"}

		result, err := adapter.ParseAndExecute(templateName, data)
		assert.NoError(t, err)
		assert.Contains(t, result, "Hello, World!")
	})

	t.Run("template file does not exist", func(t *testing.T) {
		templateName := "nonexistent_template.html"
		data := map[string]string{"Name": "World"}

		_, err := adapter.ParseAndExecute(templateName, data)
		assert.Error(t, err)
	})
}

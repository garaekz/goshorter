package sendmail

import (
	"net/smtp"
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

func (m *MockSMTPSender) SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	args := m.Called(addr, a, from, to, msg)
	return args.Error(0)
}

func (m *MockTemplateParser) ParseAndExecute(templateName string, data interface{}) (string, error) {
	args := m.Called(templateName, data)
	return args.String(0), args.Error(1)
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
	err := mailer.SendTemplateEmail("t@t.io", "Subject", "template.html", nil)

	assert.NoError(t, err)
}

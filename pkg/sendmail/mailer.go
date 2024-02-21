package sendmail

import (
	"bytes"
	"fmt"
	"html/template"
	"net/smtp"
	"path/filepath"
	"time"

	"github.com/garaekz/goshorter/pkg/url"
)

// SMTPSender defines the interface for sending emails.
type SMTPSender interface {
	SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// TemplateParser defines the interface for parsing and executing email templates.
type TemplateParser interface {
	ParseAndExecute(templateName string, data interface{}) (string, error)
}

// Mailer is a mailer that sends emails using SMTP and parses email templates.
type Mailer struct {
	Host      string
	Username  string
	Password  string
	Port      int
	FromEmail string
	FromName  string
	Sender    SMTPSender
	Templates TemplateParser
}

// SMTPAdapter is an adapter for the smtp.SendMail function.
type SMTPAdapter struct{}

// SendMail sends an email using the smtp.SendMail function.
func (SMTPAdapter) SendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	return smtp.SendMail(addr, a, from, to, msg)
}

// TemplateAdapter is an adapter for parsing and executing email templates using the html/template package.
type TemplateAdapter struct{}

// ParseAndExecute parses and executes an email template using the html/template package.
func (TemplateAdapter) ParseAndExecute(templateName string, data interface{}) (string, error) {
	t, err := template.ParseFiles(templateName)
	if err != nil {
		return "", fmt.Errorf("error parsing template: %w", err)
	}

	var body bytes.Buffer
	if err := t.Execute(&body, data); err != nil {
		return "", fmt.Errorf("error executing template: %w", err)
	}

	return body.String(), nil
}

// SendTemplateEmail sends an email using the specified SMTP settings and email template.
func (m Mailer) SendTemplateEmail(to, subject, templateName string, data interface{}) error {
	renderedTemplate, err := m.Templates.ParseAndExecute(templateName, data)
	if err != nil {
		return err
	}

	mimeHeaders := fmt.Sprintf("From: %s <%s>\nTo: %s\nSubject: %s\nMIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n", m.FromName, m.FromEmail, to, subject)
	fullMessage := mimeHeaders + renderedTemplate

	address := fmt.Sprintf("%s:%d", m.Host, m.Port)
	var auth smtp.Auth
	if m.Username != "" && m.Password != "" {
		auth = smtp.PlainAuth("", m.Username, m.Password, m.Host)
	}

	return m.Sender.SendMail(address, auth, m.FromEmail, []string{to}, []byte(fullMessage))
}

// SendValidateAccountMail sends a validate account email.
func (m Mailer) SendValidateAccountMail(to, userID, baseURL, secret string, port int) error {
	subject := "Welcome to GoShorter! Please verify your email address."
	templatePath, err := filepath.Abs("./templates/mail/verify_email.html")
	if err != nil {
		return fmt.Errorf("error getting template path: %w", err)
	}

	fullBaseURL := fmt.Sprintf("%s%s", baseURL, getPortSuffix(port))
	verificationURL := url.TemporarySignedRoute(fullBaseURL, secret, "/verify", 24*time.Hour, map[string]string{"id": userID})

	data := struct {
		URL  string
		Year int
	}{
		URL:  verificationURL,
		Year: time.Now().Year(),
	}

	return m.SendTemplateEmail(to, subject, templatePath, data)
}

// getPortSuffix returns the port or an empty string if it's 80 or 443.
func getPortSuffix(port int) string {
	if port == 80 || port == 443 {
		return ""
	}
	return fmt.Sprintf(":%d", port)
}

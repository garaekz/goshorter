package sendmail

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/smtp"
	"path/filepath"
	"time"

	"github.com/garaekz/goshorter/pkg/url"
)

// Mailer is a mailer that sends emails using SMTP.
type Mailer struct {
	Host      string
	Username  string
	Password  string
	Port      int
	FromEmail string
	FromName  string
}

// SendMail sends an email.
func (m Mailer) SendMail(ctx context.Context, to, subject, templateName string, data interface{}) error {
	t, err := template.ParseFiles(templateName)
	if err != nil {
		return fmt.Errorf("error parsing template: %w", err)
	}

	var body bytes.Buffer
	mimeHeaders := "From: " + m.FromName + " <" + m.FromEmail + ">\n" +
		"To: " + to + "\n" +
		"Subject: " + subject + "\n" +
		"MIME-version: 1.0;\n" +
		"Content-Type: text/html; charset=\"UTF-8\";\n\n"
	body.Write([]byte(mimeHeaders))

	if err := t.Execute(&body, data); err != nil {
		return fmt.Errorf("error executing template: %w", err)
	}

	address := fmt.Sprintf("%s:%d", m.Host, m.Port)
	var auth smtp.Auth = nil
	if m.Username != "" && m.Password != "" {
		auth = smtp.PlainAuth("", m.Username, m.Password, m.Host)
	}

	if err := smtp.SendMail(address, auth, m.FromEmail, []string{to}, body.Bytes()); err != nil {
		return err
	}

	return nil
}

// SendValidateAccountMail sends a validate account email.
func (m Mailer) SendValidateAccountMail(ctx context.Context, to, userID, baseURL, secret string, port int) error {
	subject := "Welcome to GoShorter! Please verify your email address."
	templatePath, err := filepath.Abs("./templates/mail/verify_email.html")
	if err != nil {
		return fmt.Errorf("error getting template path: %w", err)
	}

	signer := &url.HMACSigner{SecretKey: secret}
	fullBaseURL := fmt.Sprintf("%s%s", baseURL, getPortSuffix(port))
	verificationURL := url.TemporarySignedRoute(fullBaseURL, signer, "/verify", 24*time.Hour, map[string]string{"id": userID})

	data := struct {
		URL  string
		Year int
	}{
		URL:  verificationURL,
		Year: time.Now().Year(),
	}

	return m.SendMail(ctx, to, subject, templatePath, data)
}

// getPortSuffix returns the port or an empty string if it's 80 or 443.
func getPortSuffix(port int) string {
	if port == 80 || port == 443 {
		return ""
	}
	return fmt.Sprintf(":%d", port)
}

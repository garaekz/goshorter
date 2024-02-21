package url

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"time"
)

// HMACSigner is a signer that uses HMAC with SHA-256 to generate signatures.
type HMACSigner struct {
	SecretKey string
}

// GenerateHash generates a Hash for the given data using HMAC with SHA-256.
func (h *HMACSigner) GenerateHash(data string) string {
	hasher := hmac.New(sha256.New, []byte(h.SecretKey))
	_, err := hasher.Write([]byte(data))
	if err != nil {
		return ""
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// SignedRoute creates a signed URL for the given path and parameters.
func SignedRoute(baseURL, secret, path string, params map[string]string, expiration *time.Time) string {
	var expirationStr string
	if expiration != nil {
		expirationStr = strconv.FormatInt(expiration.Unix(), 10)
	}

	signature := generateSignature(secret, path, params, expirationStr)
	if len(params) > 0 {
		path += "?"
	}
	for k, v := range params {
		path += fmt.Sprintf("&%s=%s", k, url.QueryEscape(v))
	}
	return fmt.Sprintf("%s%s&sig=%s", baseURL, path, url.QueryEscape(signature))
}

// VerifySignature verifies the signature of a signed URL.
func VerifySignature(path, providedSignature, expiration, secret string, params map[string]string) bool {
	generatedSignature := generateSignature(secret, path, params, expiration)

	// Decode the provided signature before comparing
	providedDecoded, err := url.QueryUnescape(providedSignature)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(providedDecoded), []byte(generatedSignature))
}

// TemporarySignedRoute creates a signed URL for the given path and parameters with an expiration time.
func TemporarySignedRoute(baseURL, secret string, path string, duration time.Duration, params map[string]string) string {
	expiration := time.Now().Add(duration)
	return SignedRoute(baseURL, secret, path, params, &expiration)
}

// generateSignature generates a signature for the given path and parameters.
func generateSignature(secret, path string, params map[string]string, expiration string) string {
	if params == nil {
		params = make(map[string]string)
	}

	// Add expiration to the parameters if provided
	if expiration != "" {
		params["exp"] = expiration
	}

	// Order the parameters by key to ensure consistent signature
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var paramString string
	for _, k := range keys {
		paramString += fmt.Sprintf("&%s=%s", k, url.QueryEscape(params[k]))
	}
	if len(paramString) > 0 {
		paramString = paramString[1:] // Eliminar '&' inicial
	}

	signatureData := fmt.Sprintf("%s?%s", path, paramString)
	signer := &HMACSigner{SecretKey: secret}
	return signer.GenerateHash(signatureData)
}

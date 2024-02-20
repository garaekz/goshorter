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

// Signer defines an interface for generating signatures for URLs.
type Signer interface {
	GenerateSignature(data string) string
}

// HMACSigner implements the Signer interface using HMAC with SHA-256.
type HMACSigner struct {
	SecretKey string
}

// GenerateSignature generates a signature for the given data using HMAC with SHA-256.
func (h *HMACSigner) GenerateSignature(data string) string {
	hasher := hmac.New(sha256.New, []byte(h.SecretKey))
	hasher.Write([]byte(data))
	return hex.EncodeToString(hasher.Sum(nil))
}

// SignedRoute creates a signed URL for the given path and parameters.
func SignedRoute(baseURL string, signer Signer, path string, params map[string]string, expiration *time.Time) string {
	if params == nil {
		params = make(map[string]string)
	}

	if expiration != nil {
		params["exp"] = strconv.FormatInt(expiration.Unix(), 10)
	}

	// Ordered to ensure consistent signatures
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
		paramString = "?" + paramString[1:]
	}

	signatureData := fmt.Sprintf("%s%s", path, paramString)
	signature := signer.GenerateSignature(signatureData)

	return fmt.Sprintf("%s%s%s&sig=%s", baseURL, path, paramString, url.QueryEscape(signature))
}

// TemporarySignedRoute creates a signed URL for the given path and parameters with an expiration time.
func TemporarySignedRoute(baseURL string, signer Signer, path string, duration time.Duration, params map[string]string) string {
	expiration := time.Now().Add(duration)
	return SignedRoute(baseURL, signer, path, params, &expiration)
}

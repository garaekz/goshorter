package url

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"
	"time"
)

func TestGenerateHash(t *testing.T) {
	secretKey := "mySecretKey"
	data := "myData"

	signer := &HMACSigner{
		SecretKey: secretKey,
	}

	expectedHash := hmac.New(sha256.New, []byte(secretKey))
	_, err := expectedHash.Write([]byte(data))
	if err != nil {
		t.Errorf("Error writing to hash: %s", err)
	}
	expectedHashString := hex.EncodeToString(expectedHash.Sum(nil))

	actualHash := signer.GenerateHash(data)

	if actualHash != expectedHashString {
		t.Errorf("Expected hash: %s, but got: %s", expectedHashString, actualHash)
	}

}

func TestSignedRoute(t *testing.T) {
	baseURL := "https://example.com"
	secret := "mySecretKey"
	path := "/path"
	params := map[string]string{
		"param1": "value1",
		"param2": "value2",
	}
	expiration := time.Now().Add(time.Hour)

	expectedExpirationStr := strconv.FormatInt(expiration.Unix(), 10)
	expectedSignature := GenerateSignature(secret, path, params, expectedExpirationStr)
	paramString := generateParamString(params, expectedExpirationStr)
	expectedURL := fmt.Sprintf("%s%s?%s&sig=%s", baseURL, path, paramString, expectedSignature)

	actualURL := SignedRoute(baseURL, secret, path, params, &expiration)

	if actualURL != expectedURL {
		t.Errorf("Expected URL: %s, but got: %s", expectedURL, actualURL)
	}

	actualURL = TemporarySignedRoute(baseURL, secret, path, time.Hour, params)

	if actualURL != expectedURL {
		t.Errorf("Expected URL: %s, but got: %s", expectedURL, actualURL)
	}
}

func TestGenerateSignature(t *testing.T) {
	// Definir casos de prueba
	tests := []struct {
		name       string
		secret     string
		path       string
		params     map[string]string
		expiration string
		want       string
	}{
		{
			name:       "Simple case",
			secret:     "secretKey",
			path:       "/test/path",
			params:     map[string]string{"param1": "value1", "param2": "value2"},
			expiration: "1234567890",
			want:       "d0df9f01100d0bbe653a086a5df18286fbd929751b8e1b49fc08c5fea9db5fd6",
		},
		{
			name:       "With empty params",
			secret:     "secretKey",
			path:       "/test/empty",
			params:     nil,
			expiration: "1234567890",
			want:       "3981b53f86b9d6c8002af9be1afe84165c0ee040ad74de4ebde444cdbcffbe48",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := &HMACSigner{SecretKey: tt.secret}

			got := signer.GenerateHash(fmt.Sprintf("%s?%s", tt.path, generateParamString(tt.params, tt.expiration)))

			if got != tt.want {
				t.Errorf("GenerateSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateParamString(t *testing.T) {
	tests := []struct {
		name       string
		params     map[string]string
		expiration string
		want       string
	}{
		{
			name:       "No parameters, no expiration",
			params:     nil,
			expiration: "",
			want:       "",
		},
		{
			name: "Only expiration",
			params: map[string]string{
				"exp": "123456",
			},
			expiration: "123456",
			want:       "exp=123456",
		},
		{
			name: "Multiple parameters, including exp",
			params: map[string]string{
				"param1": "value1",
				"param2": "value2",
				"exp":    "123456",
			},
			expiration: "123456",
			want:       "param1=value1&param2=value2&exp=123456",
		},
		{
			name: "Multiple parameters, exp last",
			params: map[string]string{
				"param1": "value1",
				"param2": "value2",
			},
			expiration: "123456",
			want:       "param1=value1&param2=value2&exp=123456",
		},
		{
			name: "Parameters need URL encoding",
			params: map[string]string{
				"email": "test@example.com",
				"name":  "John Doe",
			},
			expiration: "",
			want:       "email=test%40example.com&name=John+Doe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateParamString(tt.params, tt.expiration)
			if got != tt.want {
				t.Errorf("generateParamString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

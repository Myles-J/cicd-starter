package auth

import (
	"net/http"
	"testing"
)

const expectedErr = "malformed authorization header"

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		input          http.Header
		expectedKey    string
		expectedErrMsg string
	}{
		{
			name: "Valid API Key",
			input: http.Header{
				"Authorization": []string{"ApiKey test"},
			},
			expectedKey:    "test",
			expectedErrMsg: "",
		},
		{
			name:           "Missing Header",
			input:          http.Header{},
			expectedKey:    "",
			expectedErrMsg: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "Malformed Header - Invalid Scheme",
			input: http.Header{
				"Authorization": []string{"Bearer Token"},
			},
			expectedKey:    "",
			expectedErrMsg: expectedErr,
		},
		{
			name: "Malformed Header - Missing Key",
			input: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:    "",
			expectedErrMsg: expectedErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.input)

			// Check the key
			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			// Check the error
			if tt.expectedErrMsg == "" {
				if err != nil {
					t.Errorf("expected no error, got %q", err.Error())
				}
			} else {
				if err == nil {
					t.Errorf("expected error %q, got nil", tt.expectedErrMsg)
				} else if err.Error() != tt.expectedErrMsg {
					t.Errorf("expected error %q, got %q", tt.expectedErrMsg, err.Error())
				}
			}
		})
	}
}
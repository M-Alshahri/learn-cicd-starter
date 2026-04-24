package auth

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		value     string
		expect    string
		expectErr string
	}{
		{
			name:      "No Auth Key & Header",
			expectErr: "no authorization header",
		},
		{
			name:      "No Auth Header",
			key:       "Authorization",
			expectErr: "no authorization header",
		},
		{
			name:      "Unknown or malformed Auth Header Value",
			key:       "Authorization",
			value:     "-",
			expectErr: "malformed authorization header",
		},
		{
			name:      "Unknown or malformed Auth Header",
			key:       "Authorization",
			value:     "Bearer xxxxxx",
			expectErr: "malformed authorization header",
		},
		{
			name:      "Valid Auth Header",
			key:       "Authorization",
			value:     "ApiKey xxxxxx",
			expect:    "xxxxxx",
			expectErr: "not expecting an error",
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("TestGetAPIKey Case #%v test case name: %v", i, test.name), func(t *testing.T) {
			header := http.Header{}
			header.Add(test.key, test.value)
			output, err := GetAPIKey(header)
			if err != nil {
				if strings.Contains(err.Error(), test.expectErr) {
					return
				}
				t.Errorf("Unexpected: TestGetAPIKey:%v\n", err)
				return
			}
			if output != test.expect {
				t.Errorf("Unexpected: TestGetAPIKey:%s", output)
				return
			}

		})
	}
}

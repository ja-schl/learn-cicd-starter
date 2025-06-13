package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		key     string
		val     string
		wantOut string
		wantErr error
	}{
		"Valid header": {
			key:     "Authorization",
			val:     "ApiKey abcd",
			wantOut: "abcd",
			wantErr: nil,
		},
		"No Auth Header": {
			key:     "",
			val:     "ApiKey abcd",
			wantOut: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"Malformed Auth Header 1": {
			key:     "Authorization",
			val:     "abcd",
			wantOut: "",
			wantErr: errors.New("malformed authorization header"),
		},
		"Malformed Auth Header 2": {
			key:     "Authorization",
			val:     "Bearer abcd",
			wantOut: "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			headers := http.Header{}
			headers.Add(tc.key, tc.val)
			got, err := GetAPIKey(headers)
			if err != nil {
				if err.Error() == tc.wantErr.Error() {
					return
				}
				t.Fatalf("Got unexpected error: %v", err)
			}
			if !reflect.DeepEqual(tc.wantOut, got) {
				t.Fatalf("expected: %#v, got: %#v", tc.wantOut, got)
			}
		})

	}
}

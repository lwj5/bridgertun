package agent

import "testing"

func TestBuildDialURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rawURL  string
		want    string
		wantErr bool
	}{
		{name: "preserves websocket url", rawURL: "wss://relay.example.com/v1/agent/connect", want: "wss://relay.example.com/v1/agent/connect"},
		{name: "rejects invalid url", rawURL: "://bad", wantErr: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := buildDialURL(test.rawURL)
			if test.wantErr {
				if err == nil {
					t.Fatalf("buildDialURL(%q) error = nil, want non-nil", test.rawURL)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildDialURL(%q) error = %v", test.rawURL, err)
			}
			if got != test.want {
				t.Fatalf("buildDialURL(%q) = %q, want %q", test.rawURL, got, test.want)
			}
		})
	}
}

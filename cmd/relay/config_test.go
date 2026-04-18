package main

import "testing"

func TestParseCIDRList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		wantLen int
		wantErr bool
	}{
		{name: "empty", raw: "", wantLen: 0},
		{name: "ipv4", raw: "10.0.0.1", wantLen: 1},
		{name: "cidr and ipv6", raw: "10.0.0.0/24,2001:db8::1", wantLen: 2},
		{name: "invalid", raw: "not-a-cidr", wantErr: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseCIDRList(test.raw)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseCIDRList(%q) error = nil, want non-nil", test.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCIDRList(%q) error = %v", test.raw, err)
			}
			if len(got) != test.wantLen {
				t.Fatalf("len(parseCIDRList(%q)) = %d, want %d", test.raw, len(got), test.wantLen)
			}
		})
	}
}

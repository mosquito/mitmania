package config

import "testing"

func TestParseSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{in: "64k", want: 64 << 10},
		{in: "64K", want: 64 << 10},
		{in: "1m", want: 1 << 20},
		{in: "1M", want: 1 << 20},
		{in: "1g", want: 1 << 30},
		{in: "512", want: 512},
		{in: "0", want: 0},
		{in: "", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "-5", wantErr: true},
		{in: "-5k", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseSize(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseSize(%q): expected error, got %d", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSize(%q): unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseSize(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

package daemoncli

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want Action
		err  bool
	}{
		{name: "run", want: Run},
		{name: "help", args: []string{"help"}, want: Help},
		{name: "long help", args: []string{"--help"}, want: Help},
		{name: "short help", args: []string{"-h"}, want: Help},
		{name: "version", args: []string{"version"}, want: Version},
		{name: "long version", args: []string{"--version"}, want: Version},
		{name: "typo", args: []string{"--verison"}, err: true},
		{name: "multiple", args: []string{"--help", "extra"}, err: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.args)
			if tt.err {
				if err == nil {
					t.Fatalf("Parse(%v) unexpectedly succeeded with %q", tt.args, got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("Parse(%v)=(%q,%v) want %q", tt.args, got, err, tt.want)
			}
		})
	}
}

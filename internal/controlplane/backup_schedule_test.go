package controlplane

import (
	"testing"
	"time"
)

func TestBackupScheduleMatchesUTCBoundedCronGrammar(t *testing.T) {
	at := time.Date(2026, 9, 7, 18, 30, 0, 0, time.UTC) // Monday
	cases := []struct {
		schedule string
		want     bool
	}{
		{"30 18 * * 1", true}, {"*/15 18 * * 1-5", true}, {"0 18 * * 1", false}, {"30 18 * * 0", false}, {"30 18 * * 7", false}, {"30 18 7 9 *", true},
	}
	for _, tc := range cases {
		got, err := BackupScheduleMatchesUTC(tc.schedule, at)
		if err != nil || got != tc.want {
			t.Fatalf("schedule %q got=%v err=%v want=%v", tc.schedule, got, err, tc.want)
		}
	}
	for _, bad := range []string{"* * *", "61 * * * *", "* 24 * * *", "*/0 * * * *", "foo * * * *", "10-2 * * * *"} {
		if _, err := BackupScheduleMatchesUTC(bad, at); err == nil {
			t.Fatalf("invalid schedule %q accepted", bad)
		}
	}
}

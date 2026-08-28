//go:build cgo && linux

package pgdriver

import (
	"database/sql"
	"testing"
	"time"
)

func TestDriverRegistered(t *testing.T) {
	found := false
	for _, name := range sql.Drivers() {
		if name == Name() {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("driver %q is not registered", Name())
	}
}

func TestParameterText(t *testing.T) {
	at := time.Date(2026, 8, 5, 12, 30, 0, 123456000, time.FixedZone("test", 3*3600+30*60))
	tests := []struct {
		in   any
		want string
	}{
		{"hello", "hello"},
		{[]byte(`{"ok":true}`), `{"ok":true}`},
		{true, "true"},
		{int64(42), "42"},
		{at, "2026-08-05T09:00:00.123456Z"},
	}
	for _, test := range tests {
		got, err := parameterText(test.in)
		if err != nil {
			t.Fatalf("parameterText(%T): %v", test.in, err)
		}
		if got != test.want {
			t.Fatalf("parameterText(%T)=%q want %q", test.in, got, test.want)
		}
	}
}

func TestDecodeColumn(t *testing.T) {
	value, err := decodeColumn(20, "42")
	if err != nil || value != int64(42) {
		t.Fatalf("decode int8: value=%v err=%v", value, err)
	}
	value, err = decodeColumn(3802, `{"ok":true}`)
	if err != nil || string(value.([]byte)) != `{"ok":true}` {
		t.Fatalf("decode jsonb: value=%v err=%v", value, err)
	}
	value, err = decodeColumn(1184, "2026-08-05 09:00:00.123456+00")
	if err != nil || value.(time.Time).UTC().Format(time.RFC3339Nano) != "2026-08-05T09:00:00.123456Z" {
		t.Fatalf("decode timestamptz: value=%v err=%v", value, err)
	}
}

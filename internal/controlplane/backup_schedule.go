package controlplane

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type cronFieldSpec struct {
	min int
	max int
}

func cronFieldMatches(raw string, value int, spec cronFieldSpec, sundayAlias bool) (bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false, fmt.Errorf("empty cron field")
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return false, fmt.Errorf("empty cron list item")
		}
		step := 1
		base := part
		if strings.Contains(part, "/") {
			pieces := strings.Split(part, "/")
			if len(pieces) != 2 || strings.TrimSpace(pieces[1]) == "" {
				return false, fmt.Errorf("invalid cron step %q", part)
			}
			base = strings.TrimSpace(pieces[0])
			parsed, err := strconv.Atoi(strings.TrimSpace(pieces[1]))
			if err != nil || parsed <= 0 || parsed > spec.max-spec.min+1 {
				return false, fmt.Errorf("invalid cron step %q", part)
			}
			step = parsed
		}
		start, end := spec.min, spec.max
		switch {
		case base == "*":
		case strings.Contains(base, "-"):
			pieces := strings.Split(base, "-")
			if len(pieces) != 2 {
				return false, fmt.Errorf("invalid cron range %q", base)
			}
			var err error
			start, err = strconv.Atoi(strings.TrimSpace(pieces[0]))
			if err != nil {
				return false, fmt.Errorf("invalid cron range %q", base)
			}
			end, err = strconv.Atoi(strings.TrimSpace(pieces[1]))
			if err != nil {
				return false, fmt.Errorf("invalid cron range %q", base)
			}
		default:
			parsed, err := strconv.Atoi(base)
			if err != nil {
				return false, fmt.Errorf("invalid cron value %q", base)
			}
			start, end = parsed, parsed
		}
		if start < spec.min || start > spec.max || end < spec.min || end > spec.max {
			return false, fmt.Errorf("cron value outside %d..%d", spec.min, spec.max)
		}
		if start > end {
			return false, fmt.Errorf("descending cron range is not supported")
		}
		candidates := []int{value}
		if sundayAlias && value == 0 {
			candidates = append(candidates, 7)
		}
		for _, candidate := range candidates {
			if candidate >= start && candidate <= end && (candidate-start)%step == 0 {
				return true, nil
			}
		}
	}
	return false, nil
}

// BackupScheduleMatchesUTC evaluates the supported five-field cron grammar in UTC.
// V1 intentionally excludes names, seconds and timezone extensions so the schedule
// has identical semantics on every control-plane replica.
func BackupScheduleMatchesUTC(schedule string, at time.Time) (bool, error) {
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return false, fmt.Errorf("schedule must contain exactly five cron fields")
	}
	at = at.UTC()
	values := []int{at.Minute(), at.Hour(), at.Day(), int(at.Month()), int(at.Weekday())}
	specs := []cronFieldSpec{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	for i := range fields {
		ok, err := cronFieldMatches(fields[i], values[i], specs[i], i == 4)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

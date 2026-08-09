package main

import "testing"

// TestMediaConfigurationRejectsPartialEnablement keeps the runtime aligned with
// the chart's fail-closed storage sentinel and prevents silently ignored paths.
func TestMediaConfigurationRejectsPartialEnablement(t *testing.T) {
	for name, values := range map[string][3]string{
		"unknown switch":       {"yes", "", ""},
		"root while disabled":  {"false", "/not/used", ""},
		"limit while disabled": {"", "", "2"},
		"missing root":         {"true", "", "2"},
		"missing concurrency":  {"true", "/reviewed", ""},
		"zero concurrency":     {"true", "/reviewed", "0"},
		"excess concurrency":   {"true", "/reviewed", "4097"},
		"invalid concurrency":  {"true", "/reviewed", "many"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := mediaConfiguration(values[0], values[1], values[2]); err == nil {
				t.Fatal("mediaConfiguration() unexpectedly succeeded")
			}
		})
	}
}

// TestMediaConfigurationHasNoInventedDefaults verifies disabled startup and
// exact operator-supplied enablement without choosing Pi values in code.
func TestMediaConfigurationHasNoInventedDefaults(t *testing.T) {
	enabled, options, err := mediaConfiguration("", "", "")
	if err != nil || enabled || options.Root != "" || options.MaxConcurrent != 0 {
		t.Fatalf("disabled configuration = enabled=%t options=%+v err=%v", enabled, options, err)
	}
	enabled, options, err = mediaConfiguration("true", "/reviewed", "7")
	if err != nil || !enabled || options.Root != "/reviewed" || options.MaxConcurrent != 7 {
		t.Fatalf("enabled configuration = enabled=%t options=%+v err=%v", enabled, options, err)
	}
}

package main

import (
	"errors"
	"testing"
)

func TestPercentileUsesNearestRank(t *testing.T) {
	values := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if got := percentile(values, 0.50); got != 5 {
		t.Fatalf("median percentile = %v, want 5", got)
	}
	if got := percentile(values, 0.95); got != 10 {
		t.Fatalf("p95 percentile = %v, want 10", got)
	}
}

func TestRunCaseRetainsIntermittentFailureEvidence(t *testing.T) {
	calls := 0
	result := runCase("intermittent", 3, 0, func(int) error {
		calls++
		if calls == 2 {
			return errors.New("sample failure")
		}
		return nil
	})
	if result["samples"] != 2 || result["errors"] != 1 {
		t.Fatalf("unexpected counts: %#v", result)
	}
	messages, ok := result["error_samples"].([]string)
	if !ok || len(messages) != 1 || messages[0] != "sample failure" {
		t.Fatalf("intermittent failure evidence missing: %#v", result)
	}
}

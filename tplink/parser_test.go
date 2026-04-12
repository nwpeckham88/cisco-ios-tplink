package tplink

import (
	"reflect"
	"testing"
)

func TestJsToGoHexAndArrays(t *testing.T) {
	if got := jsToGo("0xFF"); got != 255 {
		t.Fatalf("jsToGo hex = %#v", got)
	}
	got, ok := jsToGo("[0xFF, 0x01]").([]any)
	if !ok {
		t.Fatalf("expected []any")
	}
	if len(got) != 2 {
		t.Fatalf("unexpected array length %#v", got)
	}
	if _, ok := got[0].(float64); !ok {
		t.Fatalf("expected float64 element type, got %#v", got[0])
	}
	if _, ok := got[1].(float64); !ok {
		t.Fatalf("expected float64 element type, got %#v", got[1])
	}
	if asInt(got[0]) != 255 || asInt(got[1]) != 1 {
		t.Fatalf("unexpected array %#v", got)
	}
}

func TestJsToGoObjectWithSingleQuotes(t *testing.T) {
	v := jsToGo("{names: ['Default', ''], state: 1}")
	obj, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected object")
	}
	names, ok := obj["names"].([]any)
	if !ok || len(names) != 2 {
		t.Fatalf("unexpected names %#v", obj["names"])
	}
	if names[0] != "Default" || names[1] != "" {
		t.Fatalf("unexpected names %v", names)
	}
	if asInt(obj["state"]) != 1 {
		t.Fatalf("unexpected state %#v", obj["state"])
	}
}

func TestExtractVarNewArray(t *testing.T) {
	html := `<html><script>var foo = new Array(10, 20, 30);</script></html>`
	v := extractVar(html, "foo")
	a, ok := v.([]any)
	if !ok {
		t.Fatalf("expected array, got %#v", v)
	}
	if len(a) != 3 || asInt(a[0]) != 10 || asInt(a[2]) != 30 {
		t.Fatalf("unexpected array %#v", a)
	}
}

func TestExtractVarExactName(t *testing.T) {
	html := `<html><script>var qosMode = 2; var qosModeExtra = 99;</script></html>`
	if got := extractVar(html, "qosMode"); asInt(got) != 2 {
		t.Fatalf("expected 2, got %#v", got)
	}
}

func TestBitsRoundTrip(t *testing.T) {
	ports := []int{1, 3, 5, 7}
	mask := PortsToBits(ports)
	got := BitsToPorts(mask, 8)
	if !reflect.DeepEqual(got, ports) {
		t.Fatalf("roundtrip mismatch got=%v want=%v", got, ports)
	}
}

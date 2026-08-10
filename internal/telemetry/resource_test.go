package telemetry

import (
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

func attrValue(t *testing.T, set attribute.Set, key string) (string, bool) {
	t.Helper()
	v, ok := set.Value(attribute.Key(key))
	if !ok {
		return "", false
	}
	return v.AsString(), true
}

func TestBuildResource_DefaultsServiceName(t *testing.T) {
	res, err := buildResource("")
	if err != nil {
		t.Fatalf("buildResource: %v", err)
	}
	set := attribute.NewSet(res.Attributes()...)
	got, ok := attrValue(t, set, "service.name")
	if !ok || got != defaultServiceName {
		t.Fatalf("service.name = %q, ok=%v, want %q", got, ok, defaultServiceName)
	}
}

func TestBuildResource_OverridesServiceName(t *testing.T) {
	res, err := buildResource("service.name=custom-proxy")
	if err != nil {
		t.Fatalf("buildResource: %v", err)
	}
	set := attribute.NewSet(res.Attributes()...)
	got, _ := attrValue(t, set, "service.name")
	if got != "custom-proxy" {
		t.Fatalf("service.name = %q, want %q", got, "custom-proxy")
	}
}

func TestBuildResource_ParsesExtraAttrs(t *testing.T) {
	res, err := buildResource("team=security,env=prod")
	if err != nil {
		t.Fatalf("buildResource: %v", err)
	}
	set := attribute.NewSet(res.Attributes()...)
	if got, _ := attrValue(t, set, "team"); got != "security" {
		t.Errorf("team = %q, want security", got)
	}
	if got, _ := attrValue(t, set, "env"); got != "prod" {
		t.Errorf("env = %q, want prod", got)
	}
}

func TestBuildResource_AlwaysIncludesInstanceID(t *testing.T) {
	res, err := buildResource("")
	if err != nil {
		t.Fatalf("buildResource: %v", err)
	}
	set := attribute.NewSet(res.Attributes()...)
	got, ok := attrValue(t, set, "service.instance.id")
	if !ok || got == "" {
		t.Fatalf("service.instance.id missing or empty")
	}
}

func TestBuildResource_RejectsMalformedPair(t *testing.T) {
	if _, err := buildResource("not-a-kv-pair"); err == nil {
		t.Fatalf("expected an error for a pair with no '='")
	}
}

func TestBuildResource_RejectsEmptyKey(t *testing.T) {
	if _, err := buildResource("=value"); err == nil {
		t.Fatalf("expected an error for an empty key")
	}
}

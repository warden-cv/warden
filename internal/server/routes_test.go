package server

import "testing"

func TestEveryAPIRouteHasUniqueSecurityClassification(t *testing.T) {
	a := &app{}
	seen := map[string]bool{}
	for _, route := range a.apiRoutes() {
		p := route.Policy
		if p.Path == "" || p.Path[:4] != "/api" || route.Handler == nil {
			t.Fatalf("invalid route: %+v", p)
		}
		if seen[p.Path] {
			t.Fatalf("duplicate route policy for %s", p.Path)
		}
		seen[p.Path] = true
		switch p.Boundary {
		case "public", "session":
			if p.Capability != "" {
				t.Fatalf("%s has unexpected capability %q", p.Path, p.Capability)
			}
		case "capability", "websocket":
			if p.Capability == "" {
				t.Fatalf("%s is missing a capability", p.Path)
			}
		default:
			t.Fatalf("%s has unknown boundary %q", p.Path, p.Boundary)
		}
	}
	if len(seen) != 37 {
		t.Fatalf("classified routes=%d, want 37", len(seen))
	}
}

package wardenassets

import (
	"io/fs"
	"strings"
	"testing"
)

// TestApplicationNavigationHasNoCrossSiteLink is a regression test for a
// dogfooding-discovered defect: a request to add Gantry to the public-facing
// websites leaked a hard-coded https://gantry.cv link into the authenticated
// application navigation. The application menu must only carry application
// routes, never unsolicited cross-site branding.
func TestApplicationNavigationHasNoCrossSiteLink(t *testing.T) {
	b, err := fs.ReadFile(PublicFS(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "gantry.cv") {
		t.Fatal("application frontend contains a hard-coded gantry.cv cross-site link; remove it from the Nift source and regenerate")
	}
}

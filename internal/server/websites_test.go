package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebsiteRevisionsAndPublishJob(t *testing.T) {
	configDir, root := t.TempDir(), t.TempDir()
	db, err := openDatabase(configDir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	files, err := newFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{db: db, files: files, cfg: Config{ConfigDir: configDir}}
	site := managedWebsite{Name: "Docs", Kind: "static", DocumentRoot: "/", Domains: []string{"docs.example.com"}, Enabled: true}
	if err := a.saveWebsite("account-a", &site); err != nil {
		t.Fatal(err)
	}
	site.Name = "Documentation"
	if err := a.saveWebsite("account-a", &site); err != nil {
		t.Fatal(err)
	}
	sites, _, err := a.loadWebsites()
	if err != nil || len(sites) != 1 || sites[0].Revision != 2 {
		t.Fatalf("unexpected sites: %#v, %v", sites, err)
	}
	if err := a.queueWebsiteJob("account-a", site.ID, "publish"); err != nil {
		t.Fatal(err)
	}
	a.processWebsiteJob()
	fragment, err := os.ReadFile(filepath.Join(configDir, "sites", site.ID+".caddy"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fragment), "docs.example.com") || !strings.Contains(string(fragment), "file_server") {
		t.Fatalf("unexpected fragment: %s", fragment)
	}
	_, jobs, err := a.loadWebsites()
	if err != nil || len(jobs) != 1 || jobs[0].State != "completed" {
		t.Fatalf("unexpected jobs: %#v, %v", jobs, err)
	}
}

func TestWebsiteProxyMustRemainLoopback(t *testing.T) {
	db, err := openDatabase(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	files, err := newFiles(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := &app{db: db, files: files}
	site := managedWebsite{Name: "Unsafe", Kind: "proxy", Upstream: "https://example.com", Domains: []string{"app.example.com"}, Enabled: true}
	if err := a.saveWebsite("account-a", &site); err == nil {
		t.Fatal("accepted non-loopback reverse proxy")
	}
}

func TestWebsiteRevisionConflictFailsWithoutNewRevision(t *testing.T) {
	configDir, root := t.TempDir(), t.TempDir()
	db, err := openDatabase(configDir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	files, err := newFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{db: db, files: files, cfg: Config{ConfigDir: configDir}}
	site := managedWebsite{Name: "Docs", Kind: "static", DocumentRoot: "/", Domains: []string{"docs.example.com"}, Enabled: true}
	if err := a.saveWebsite("account-a", &site); err != nil {
		t.Fatal(err)
	}
	stale := site
	site.Name = "Current"
	if err := a.saveWebsite("account-a", &site); err != nil {
		t.Fatal(err)
	}
	stale.Name = "Stale overwrite"
	if err := a.saveWebsite("account-b", &stale); err == nil {
		t.Fatal("stale website revision overwrote current configuration")
	}
	sites, _, err := a.loadWebsites()
	if err != nil || len(sites) != 1 || sites[0].Name != "Current" || sites[0].Revision != 2 {
		t.Fatalf("sites=%#v err=%v", sites, err)
	}
}

func TestCaddyRenderingQuotesPathsAndSanitizesComments(t *testing.T) {
	fragment := renderCaddyWebsite(managedWebsite{Enabled: true, Kind: "static", DocumentRoot: "/srv/a path\nheader X-Evil yes", Domains: []string{"docs.example.com"}})
	if !strings.Contains(fragment, `root * "/srv/a path\nheader X-Evil yes"`) {
		t.Fatalf("document root was not quoted: %q", fragment)
	}
	disabled := renderCaddyWebsite(managedWebsite{Name: "line\ninjection", Domains: []string{"docs.example.com"}})
	if strings.Count(disabled, "\n") != 1 {
		t.Fatalf("disabled comment contains injected line: %q", disabled)
	}
}

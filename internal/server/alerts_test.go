package server

import (
	"testing"
	"time"
)

func TestAlertRuleDurationAndResolution(t *testing.T) {
	db, err := openDatabase(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := &app{db: db}
	rule := alertRule{Name: "High CPU", Metric: "cpu", Operator: ">", Threshold: 80, DurationSeconds: 30, Severity: "critical", Enabled: true}
	if err := a.saveAlertRule("account-a", &rule); err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1000, 0)
	a.evaluateAlerts(monitorSnapshot{CPU: 90}, start)
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM alert_instances WHERE state='firing'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("alert fired before duration: count=%d err=%v", count, err)
	}
	a.evaluateAlerts(monitorSnapshot{CPU: 91}, start.Add(31*time.Second))
	if err := db.QueryRow("SELECT COUNT(*) FROM alert_instances WHERE state='firing'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("alert did not fire: count=%d err=%v", count, err)
	}
	a.evaluateAlerts(monitorSnapshot{CPU: 20}, start.Add(46*time.Second))
	if err := db.QueryRow("SELECT COUNT(*) FROM alert_instances WHERE state='resolved'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("alert did not resolve: count=%d err=%v", count, err)
	}
}

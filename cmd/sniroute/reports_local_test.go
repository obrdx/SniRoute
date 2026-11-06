package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/nyktios/sniroute/internal/client"
	"github.com/nyktios/sniroute/internal/server"
)

func TestClientHistoryWorksAfterObserverDeletesIdentity(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer ts.Close()
	cc, err := client.NewControlClient(ts.URL, server.CertPin(ts.Certificate().Raw))
	if err != nil {
		t.Fatal(err)
	}
	ob, err := client.OpenOutbox(filepath.Join(t.TempDir(), "client.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ob.Close()
	v := server.TaskView{ID: "saved-task", CreatedAt: time.Now(), Status: server.TaskCompleted}
	if err := ob.SaveTask(v); err != nil {
		t.Fatal(err)
	}
	sess := &clientSession{ob: ob, cfg: client.Config{Enrollment: client.Enrollment{Path: "expired", NodeKey: "expired"}}, runner: &client.Runner{CC: cc}}
	items, err := sess.listReports(context.Background())
	if err != nil || len(items) != 1 || items[0].ID != v.ID {
		t.Fatalf("local list: %+v %v", items, err)
	}
	rep, err := sess.loadReport(context.Background(), v.ID)
	if err != nil || rep.Task.ID != v.ID {
		t.Fatalf("local report: %+v %v", rep, err)
	}
}

func TestServerNoLongerExposesHistoricalReports(t *testing.T) {
	if err := runServer([]string{"reports", "list"}); err == nil {
		t.Fatal("server report command still available")
	}
}

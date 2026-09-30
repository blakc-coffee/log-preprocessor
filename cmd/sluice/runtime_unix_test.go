//go:build !windows

package main

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"
)

func TestUnifiedRuntimeHealthAndShutdown(t *testing.T) {
	cfg := runtimeConfig{
		DataDir:         t.TempDir(),
		DataPlaneListen: dataPlaneAddress,
		ControlListen:   controlAddress,
		Sinks:           []string{"ocsfjson"},
	}
	var logs bytes.Buffer
	rt, err := newUnifiedRuntime(cfg, &logs)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.serve(ctx, &logs) }()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	for _, endpoint := range []string{"http://127.0.0.1:9000/healthz", "http://127.0.0.1:8000/healthz"} {
		var response *http.Response
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			response, err = client.Get(endpoint)
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			cancel()
			t.Fatalf("GET %s: %v\n%s", endpoint, err, logs.String())
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			cancel()
			t.Fatalf("GET %s: %s", endpoint, response.Status)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := rt.close(); err != nil {
		t.Fatal(err)
	}
}

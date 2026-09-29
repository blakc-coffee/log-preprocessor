package tests

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestComposeFilesEnforceInternalLoopbackNetwork(t *testing.T) {
	type service struct {
		Ports    []string `yaml:"ports"`
		Networks []string `yaml:"networks"`
	}
	type network struct {
		Internal bool `yaml:"internal"`
	}
	type compose struct {
		Services map[string]service `yaml:"services"`
		Networks map[string]network `yaml:"networks"`
	}
	for _, name := range []string{"docker-compose.yml", "docker-compose.airgap-test.yml"} {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(projectPath(name))
			if err != nil {
				t.Fatal(err)
			}
			var cfg compose
			if err := yaml.Unmarshal(b, &cfg); err != nil {
				t.Fatal(err)
			}
			ulpf, ok := cfg.Services["ulpf"]
			if !ok {
				t.Fatal("ulpf service is missing")
			}
			if len(ulpf.Networks) != 1 || !cfg.Networks[ulpf.Networks[0]].Internal {
				t.Fatalf("ulpf network is not internal: %+v", cfg.Networks)
			}
			wantPorts := map[string]bool{"127.0.0.1:8000:8000": false, "127.0.0.1:9000:9000": false}
			for _, port := range ulpf.Ports {
				if _, expected := wantPorts[port]; !expected {
					t.Fatalf("unexpected port publication %q", port)
				}
				wantPorts[port] = true
			}
			for port, found := range wantPorts {
				if !found {
					t.Fatalf("missing loopback port publication %q", port)
				}
			}
		})
	}
}

func TestContainerAndAirgapProofContracts(t *testing.T) {
	dockerfile := mustReadPackagingFile(t, "Dockerfile")
	for _, required := range []string{"CGO_ENABLED=0 GOOS=linux", "USER nonroot:nonroot", "HEALTHCHECK", `ENTRYPOINT ["/usr/local/bin/ulpf"]`} {
		if !strings.Contains(dockerfile, required) {
			t.Fatalf("Dockerfile missing %q", required)
		}
	}
	script := mustReadPackagingFile(t, filepath.Join("scripts", "verify_airgap.sh"))
	for _, required := range []string{"--network none", "selftest --pipeline --egress --ui", "internal: true", "compose exec -T ulpf ulpf healthcheck", "AIRGAP_VERIFIED"} {
		if !strings.Contains(script, required) {
			t.Fatalf("verify_airgap.sh missing %q", required)
		}
	}
}

func mustReadPackagingFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(projectPath(path))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func projectPath(path string) string {
	_, source, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(source), "..", path)
}

package api_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Generated code is only trustworthy if it matches the spec it claims to come
// from. Checking in the output makes builds reproducible without a network
// fetch, but it also makes it possible to edit the spec and forget to
// regenerate -- or to edit the generated file directly, which the next
// regeneration would silently discard.
//
// Regenerating into a temporary file and diffing catches both.
func TestGeneratedCodeIsUpToDate(t *testing.T) {
	if testing.Short() {
		t.Skip("regeneration needs the module cache")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not on PATH")
	}

	// The config file sets `output:`, which wins over -o, so regenerate in a
	// scratch directory holding a copy of the config rather than fighting it.
	dir := t.TempDir()
	cfg, err := os.ReadFile("oapi-codegen.yaml")
	if err != nil {
		t.Fatalf("reading the generator config: %v", err)
	}
	staged := filepath.Join(dir, "oapi-codegen.yaml")
	// #nosec G703 -- dir is t.TempDir(); nothing here comes from a caller.
	if err := os.WriteFile(staged, cfg, 0o600); err != nil {
		t.Fatalf("staging the generator config: %v", err)
	}
	spec, err := filepath.Abs("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.CommandContext(t.Context(), "go", "run",
		"github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0",
		"-config", "oapi-codegen.yaml", spec)
	cmd.Dir = dir
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not run oapi-codegen (offline?): %v\n%s", err, combined)
	}

	want, err := os.ReadFile(filepath.Join(dir, "openapi_gen.go"))
	if err != nil {
		t.Fatalf("reading the regenerated file: %v", err)
	}
	got, err := os.ReadFile("openapi_gen.go")
	if err != nil {
		t.Fatalf("reading the checked-in file: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("openapi_gen.go does not match api/openapi.yaml.\n" +
			"Run `mise run generate` and commit the result.")
	}
}

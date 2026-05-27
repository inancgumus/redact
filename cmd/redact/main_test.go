package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func buildRedactBinary(ctx context.Context, t *testing.T) string {
	t.Helper()

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("cache dir: %v", err)
	}
	dir := filepath.Join(cacheDir, "redact-test")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	bin := filepath.Join(dir, "redact")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, ".")
	out, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("build redact: %v\n%s", err, out)
	}
	return bin
}

func TestScripts(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	bin := buildRedactBinary(ctx, t)

	testscript.Run(t, testscript.Params{
		Dir: "testdata/scripts",
		Setup: func(env *testscript.Env) error {
			return os.Symlink(bin, filepath.Join(env.WorkDir, "redact"))
		},
		UpdateScripts: os.Getenv("UPDATE_GOLDEN") != "",
	})
}

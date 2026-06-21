//go:build integration

package e2e

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/suckharder/xgress/internal/version"
)

// traefikChecksums pins the SHA-256 of each supported release tarball so a
// changed, truncated, or tampered download fails loudly instead of silently
// running an unverified binary. The pinned version is internal/version.TraefikVersion
// (the same Traefik whose config structs this build renders), so this tier also
// guards that the pinned Traefik actually consumes xgress's provider output.
//
// Source: https://github.com/traefik/traefik/releases/download/v3.7.5/traefik_v3.7.5_checksums.txt
var traefikChecksums = map[string]string{
	"darwin_amd64": "852fec783ecdd2761b6a78634c1f65706605654c119a60de6b267b4c5ad860fb",
	"darwin_arm64": "403fd02b59cbc655378d99450fb9da08c37559b64ec485dc8e470d7250ba5383",
	"linux_amd64":  "9da81a928fde965c2c4678698bbc28bc3f600223b14c32b35bd480bf5ec863dc",
	"linux_arm64":  "9892c0974a3958d95f049d5dad3d751ba3597bdc33e96255d2369aad3d2bfeca",
}

// ensureTraefik returns the path to a cached, checksum-verified traefik binary
// for the host OS/arch at the pinned version, downloading + extracting it once.
// Subsequent runs reuse the cached binary (validated by a sibling .ok marker).
func ensureTraefik(t *testing.T) string {
	t.Helper()
	ver := version.TraefikVersion // e.g. "v3.7.5"
	platform := runtime.GOOS + "_" + runtime.GOARCH
	want, ok := traefikChecksums[platform]
	if !ok {
		t.Skipf("no pinned traefik checksum for %s — add one to test/e2e/traefik_fetch.go to run this tier", platform)
	}

	cacheDir := filepath.Join(testSourceDir(), ".cache")
	binPath := filepath.Join(cacheDir, fmt.Sprintf("traefik-%s-%s", ver, platform))
	okMarker := binPath + ".ok"
	if isFile(binPath) && isFile(okMarker) {
		return binPath // previously downloaded + verified
	}

	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("create cache dir: %v", err)
	}

	url := fmt.Sprintf("https://github.com/traefik/traefik/releases/download/%s/traefik_%s_%s.tar.gz", ver, ver, platform)
	data, err := download(url)
	if err != nil {
		// First run needs network to fetch the pinned release; don't fail the whole
		// suite when offline — skip with a clear reason.
		t.Skipf("could not download traefik %s for %s (first run needs network): %v", ver, platform, err)
	}

	if got := sha256hex(data); got != want {
		t.Fatalf("traefik %s %s checksum mismatch:\n  got  %s\n  want %s\n(refusing to run an unverified binary)", ver, platform, got, want)
	}

	if err := extractTraefik(data, binPath); err != nil {
		t.Fatalf("extract traefik: %v", err)
	}
	if err := os.WriteFile(okMarker, []byte(want), 0o644); err != nil {
		t.Fatalf("write cache marker: %v", err)
	}
	return binPath
}

// download fetches url into memory with a bounded timeout.
func download(url string) ([]byte, error) {
	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	// Release tarballs are a few tens of MB; cap to guard against a surprise.
	return io.ReadAll(io.LimitReader(resp.Body, 128<<20))
}

// extractTraefik pulls the single "traefik" regular-file entry out of the gzipped
// tarball and writes it to dst as an executable, atomically.
func extractTraefik(tarGz []byte, dst string) error {
	gz, err := gzip.NewReader(bytes.NewReader(tarGz))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("no traefik binary found in archive")
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != "traefik" {
			continue
		}
		tmp := dst + ".tmp"
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tr); err != nil { //nolint:gosec // size-bounded by download()
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return os.Rename(tmp, dst)
	}
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// testSourceDir returns the directory of this source file, so the binary cache is
// stable regardless of the test's working directory.
func testSourceDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

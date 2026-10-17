package ui_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The canonical kit is copied into every plugin's static UI root. The copies
// are committed so the plugins stay self-contained under the self-only CSP;
// this test is the drift boundary between the canonical source and the copies.
func TestDesignSystemCopiesMatchCanonical(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	sourceDir := filepath.Join(root, "internal", "ui", "design-system")
	files := []string{"ui-kit.css", "ui-kit.js"}
	targets := map[string]string{
		"accelerator-sources": filepath.Join("plugins", "accelerator-sources", "web", "static"),
		"cloudflare-dns":      filepath.Join("plugins", "cloudflare-dns", "ui"),
		"docker-app":          filepath.Join("plugins", "docker-app", "assets", "ui"),
		"doh":                 filepath.Join("plugins", "doh", "static"),
		"ip-policy":           filepath.Join("plugins", "ip-policy", "assets", "ui"),
		"reverse-l4":          filepath.Join("plugins", "reverse-l4", "assets", "ui"),
		"shadowsocks-server":  filepath.Join("plugins", "shadowsocks-server", "assets", "ui"),
		"waf":                 filepath.Join("plugins", "waf", "assets", "ui"),
		"webdav":              filepath.Join("plugins", "webdav", "static"),
	}

	canonical := make(map[string][]byte, len(files))
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(sourceDir, name))
		if err != nil {
			t.Fatalf("read canonical %s: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("canonical %s is empty", name)
		}
		if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
			t.Fatalf("canonical %s has a UTF-8 BOM", name)
		}
		canonical[name] = data
	}

	for plugin, dir := range targets {
		plugin, dir := plugin, dir
		t.Run(plugin, func(t *testing.T) {
			t.Parallel()
			for _, name := range files {
				data, err := os.ReadFile(filepath.Join(root, dir, name))
				if err != nil {
					t.Fatalf("%s/%s: %v", dir, name, err)
				}
				if !bytes.Equal(data, canonical[name]) {
					t.Fatalf("%s/%s differs from internal/ui/design-system/%s; run node testing/ui/sync-design-system.mjs", dir, name, name)
				}
			}
		})
	}
}

func TestDesignSystemDeclaresHostThemesAndModes(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	css, err := os.ReadFile(filepath.Join(root, "internal", "ui", "design-system", "ui-kit.css"))
	if err != nil {
		t.Fatal(err)
	}
	js, err := os.ReadFile(filepath.Join(root, "internal", "ui", "design-system", "ui-kit.js"))
	if err != nil {
		t.Fatal(err)
	}

	for _, theme := range []string{"fresh-green", "sakura-day", "sakura-night", "neko-dark", "business", "light", "dark"} {
		if !strings.Contains(string(css), `[data-theme="`+theme+`"]`) {
			t.Fatalf("ui-kit.css is missing theme %q", theme)
		}
	}
	for _, token := range []string{"--ui-primary:", "--ui-bg:", "--ui-text:", "--ui-border:", "--ui-radius-lg:"} {
		if !strings.Contains(string(css), token) {
			t.Fatalf("ui-kit.css is missing token %q", token)
		}
	}
	for _, mode := range []string{"host", "standalone", "data-theme-family", "applyFromStorage", "resolveTheme"} {
		if !strings.Contains(string(js), mode) {
			t.Fatalf("ui-kit.js is missing %q", mode)
		}
	}
	if strings.Contains(string(css), "http://") || strings.Contains(string(css), "https://") {
		t.Fatal("ui-kit.css must not reference external URLs")
	}
}

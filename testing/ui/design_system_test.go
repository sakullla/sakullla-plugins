package ui_test

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
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

// uiKitTokenPair is one rendered foreground/background combination the kit
// must keep readable in every theme. Text pairs use the WCAG AA 4.5:1
// threshold; control boundaries use the WCAG non-text 3:1 threshold.
type uiKitTokenPair struct {
	fg  string
	bg  string
	min float64
	use string
}

var uiKitContrastPairs = []uiKitTokenPair{
	{"--ui-border", "--ui-surface", 3, "控件边界 on 卡片"},
	{"--ui-border-strong", "--ui-surface", 3, "控件悬停边界 on 卡片"},
	{"--ui-primary", "--ui-bg", 4.5, "链接/eyebrow/选中标签文字 on 画布"},
	{"--ui-primary", "--ui-surface", 4.5, "链接/eyebrow/选中标签文字 on 卡片"},
	{"--ui-primary", "--ui-primary-soft", 4.5, "info 徽章文字 on 软底"},
	{"--ui-on-primary", "--ui-primary", 4.5, "主按钮文字"},
	{"--ui-on-danger", "--ui-danger-button", 4.5, "危险按钮文字"},
	{"--ui-danger-text", "--ui-danger-soft", 4.5, "危险徽章文字 on 软底"},
	{"--ui-text-tertiary", "--ui-sunken", 4.5, "表头文字 on 下沉面"},
}

var (
	uiKitCSSComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	uiKitCSSBlock   = regexp.MustCompile(`(?s)([^{}]+)\{([^{}]*)\}`)
	uiKitTokenDecl  = regexp.MustCompile(`(--ui-[\w-]+)\s*:\s*([^;]+);`)
	uiKitThemeSel   = regexp.MustCompile(`^\[data-theme="([^"]+)"\]$`)
)

// TestDesignSystemContrastTokens locks the token combinations the pages
// actually render, so a theme edit cannot silently fall below WCAG AA. It
// parses the canonical CSS directly and computes the WCAG 2.x ratio in Go.
func TestDesignSystemContrastTokens(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	data, err := os.ReadFile(filepath.Join(root, "internal", "ui", "design-system", "ui-kit.css"))
	if err != nil {
		t.Fatal(err)
	}
	themes := parseUIKitThemes(t, string(data))
	for _, theme := range []string{"light", "business", "fresh-green", "sakura-day", "sakura-night", "neko-dark", "dark"} {
		theme, tokens := theme, themes[theme]
		t.Run(theme, func(t *testing.T) {
			t.Parallel()
			if tokens == nil {
				t.Fatalf("ui-kit.css is missing theme %q", theme)
			}
			surface := resolveUIKitToken(t, tokens, "--ui-surface")
			for _, pair := range uiKitContrastPairs {
				foreground := resolveUIKitToken(t, tokens, pair.fg)
				background := resolveUIKitToken(t, tokens, pair.bg)
				ratio := uiKitContrastRatio(t, foreground, background, surface)
				if ratio < pair.min {
					t.Errorf("%s on %s = %.2f, want >= %.1f (%s)", pair.fg, pair.bg, ratio, pair.min, pair.use)
				}
			}
		})
	}
}

func parseUIKitThemes(t *testing.T, cssText string) map[string]map[string]string {
	t.Helper()

	clean := uiKitCSSComment.ReplaceAllString(cssText, "")
	defaults := map[string]string{}
	themes := map[string]map[string]string{}
	for _, block := range uiKitCSSBlock.FindAllStringSubmatch(clean, -1) {
		tokens := uiKitTokenValues(block[2])
		for _, selector := range strings.Split(block[1], ",") {
			selector = strings.TrimSpace(selector)
			if selector == ":root" {
				for name, value := range tokens {
					defaults[name] = value
				}
				continue
			}
			match := uiKitThemeSel.FindStringSubmatch(selector)
			if match == nil {
				continue
			}
			if themes[match[1]] == nil {
				themes[match[1]] = map[string]string{}
			}
			for name, value := range tokens {
				themes[match[1]][name] = value
			}
		}
	}
	for _, tokens := range themes {
		for name, value := range defaults {
			if _, ok := tokens[name]; !ok {
				tokens[name] = value
			}
		}
	}
	return themes
}

func uiKitTokenValues(body string) map[string]string {
	tokens := map[string]string{}
	for _, match := range uiKitTokenDecl.FindAllStringSubmatch(body, -1) {
		tokens[match[1]] = strings.TrimSpace(match[2])
	}
	return tokens
}

func resolveUIKitToken(t *testing.T, tokens map[string]string, name string) string {
	t.Helper()

	seen := map[string]bool{}
	for {
		value, ok := tokens[name]
		if !ok {
			t.Fatalf("theme is missing token %s", name)
		}
		if seen[name] {
			t.Fatalf("token %s has a circular reference", name)
		}
		seen[name] = true
		if !strings.HasPrefix(value, "var(") {
			return value
		}
		inner := strings.TrimSuffix(strings.TrimPrefix(value, "var("), ")")
		parts := strings.SplitN(inner, ",", 2)
		reference := strings.TrimSpace(parts[0])
		if target, ok := tokens[reference]; ok && target != "" {
			name = reference
			continue
		}
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
		t.Fatalf("token %s references missing %s", name, reference)
	}
}

type uiKitColor struct {
	r, g, b float64
	a       float64
}

func parseUIKitColor(t *testing.T, value string) uiKitColor {
	t.Helper()

	text := strings.ToLower(strings.TrimSpace(value))
	switch text {
	case "white":
		return uiKitColor{r: 255, g: 255, b: 255, a: 1}
	case "black":
		return uiKitColor{a: 1}
	}
	if strings.HasPrefix(text, "#") {
		digits := strings.TrimPrefix(text, "#")
		if len(digits) == 3 || len(digits) == 4 {
			var expanded strings.Builder
			for _, digit := range digits {
				expanded.WriteRune(digit)
				expanded.WriteRune(digit)
			}
			digits = expanded.String()
		}
		if len(digits) != 6 && len(digits) != 8 {
			t.Fatalf("unsupported hex color %q", value)
		}
		channel := func(offset int) float64 {
			parsed, err := strconv.ParseUint(digits[offset:offset+2], 16, 8)
			if err != nil {
				t.Fatalf("parse color %q: %v", value, err)
			}
			return float64(parsed)
		}
		color := uiKitColor{r: channel(0), g: channel(2), b: channel(4), a: 1}
		if len(digits) == 8 {
			color.a = channel(6) / 255
		}
		return color
	}
	if strings.HasPrefix(text, "rgb(") || strings.HasPrefix(text, "rgba(") {
		open := strings.IndexByte(text, '(')
		close := strings.LastIndexByte(text, ')')
		if open < 0 || close < open {
			t.Fatalf("unsupported color %q", value)
		}
		fields := strings.FieldsFunc(text[open+1:close], func(r rune) bool {
			return r == ',' || r == '/' || unicode.IsSpace(r)
		})
		if len(fields) < 3 || len(fields) > 4 {
			t.Fatalf("unsupported color %q", value)
		}
		channel := func(index int) float64 {
			parsed, err := strconv.ParseFloat(fields[index], 64)
			if err != nil {
				t.Fatalf("parse color %q: %v", value, err)
			}
			return parsed
		}
		color := uiKitColor{r: channel(0), g: channel(1), b: channel(2), a: 1}
		if len(fields) == 4 {
			color.a = channel(3)
		}
		return color
	}
	t.Fatalf("unsupported color %q", value)
	return uiKitColor{}
}

func uiKitLinear(channel float64) float64 {
	value := channel / 255
	if value <= 0.04045 {
		return value / 12.92
	}
	return math.Pow((value+0.055)/1.055, 2.4)
}

func uiKitLuminance(color uiKitColor) float64 {
	return 0.2126*uiKitLinear(color.r) + 0.7152*uiKitLinear(color.g) + 0.0722*uiKitLinear(color.b)
}

func uiKitBlend(foreground, background uiKitColor) uiKitColor {
	alpha := foreground.a
	return uiKitColor{
		r: foreground.r*alpha + background.r*(1-alpha),
		g: foreground.g*alpha + background.g*(1-alpha),
		b: foreground.b*alpha + background.b*(1-alpha),
		a: 1,
	}
}

func uiKitContrastRatio(t *testing.T, foregroundText, backgroundText, baseText string) float64 {
	t.Helper()

	foreground := parseUIKitColor(t, foregroundText)
	background := parseUIKitColor(t, backgroundText)
	base := parseUIKitColor(t, baseText)
	if background.a < 1 {
		background = uiKitBlend(background, base)
	}
	if foreground.a < 1 {
		foreground = uiKitBlend(foreground, background)
	}
	high, low := uiKitLuminance(foreground), uiKitLuminance(background)
	if high < low {
		high, low = low, high
	}
	return (high + 0.05) / (low + 0.05)
}

// TestDesignSystemButtonFocusRing locks the shared button focus indicator.
// `.ui-btn:focus-visible` must not suppress the kit-wide outline: the ring is
// the host primary color, separated from the button edge by an offset, and the
// same color stays at or above the WCAG non-text 3:1 threshold on every
// theme's canvas and card surface (R1, R3, R4).
func TestDesignSystemButtonFocusRing(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	data, err := os.ReadFile(filepath.Join(root, "internal", "ui", "design-system", "ui-kit.css"))
	if err != nil {
		t.Fatal(err)
	}
	cssText := string(data)

	body, ok := uiKitRuleBody(cssText, ".ui-btn:focus-visible")
	if !ok {
		t.Fatal("ui-kit.css is missing the .ui-btn:focus-visible rule")
	}
	declarations := uiKitDeclarations(body)
	if strings.EqualFold(strings.TrimSpace(declarations["outline"]), "none") {
		t.Fatal(".ui-btn:focus-visible suppresses the focus outline with `outline: none`")
	}
	width, style, color := uiKitFocusOutline(t, declarations)
	if style != "solid" {
		t.Fatalf(".ui-btn:focus-visible outline style = %q, want solid", style)
	}
	if width < 2 {
		t.Fatalf(".ui-btn:focus-visible outline width = %.1fpx, want >= 2px", width)
	}
	if color != "var(--ui-primary)" {
		t.Fatalf(".ui-btn:focus-visible outline color = %q, want var(--ui-primary)", color)
	}
	offset, ok := uiKitPixels(declarations["outline-offset"])
	if !ok {
		t.Fatal(".ui-btn:focus-visible is missing a pixel outline-offset")
	}
	if offset < 2 {
		t.Fatalf(".ui-btn:focus-visible outline-offset = %.1fpx, want >= 2px", offset)
	}

	themes := parseUIKitThemes(t, cssText)
	for _, theme := range []string{"light", "business", "fresh-green", "sakura-day", "sakura-night", "neko-dark", "dark"} {
		theme, tokens := theme, themes[theme]
		t.Run(theme, func(t *testing.T) {
			t.Parallel()
			if tokens == nil {
				t.Fatalf("ui-kit.css is missing theme %q", theme)
			}
			primary := resolveUIKitToken(t, tokens, "--ui-primary")
			for _, background := range []string{"--ui-bg", "--ui-surface"} {
				base := resolveUIKitToken(t, tokens, background)
				ratio := uiKitContrastRatio(t, primary, base, base)
				if ratio < 3 {
					t.Errorf("--ui-primary on %s = %.2f, want >= 3.0 for the focus ring", background, ratio)
				}
			}
		})
	}
}

// uiKitRuleBody returns the declaration body of the first rule whose selector
// list contains selector.
func uiKitRuleBody(cssText, selector string) (string, bool) {
	clean := uiKitCSSComment.ReplaceAllString(cssText, "")
	for _, block := range uiKitCSSBlock.FindAllStringSubmatch(clean, -1) {
		for _, candidate := range strings.Split(block[1], ",") {
			if strings.TrimSpace(candidate) == selector {
				return block[2], true
			}
		}
	}
	return "", false
}

func uiKitDeclarations(body string) map[string]string {
	values := map[string]string{}
	for _, declaration := range strings.Split(body, ";") {
		name, value, ok := strings.Cut(declaration, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		values[name] = strings.TrimSpace(value)
	}
	return values
}

// uiKitFocusOutline resolves the effective width, style and color of the
// outline shorthand or its longhand properties.
func uiKitFocusOutline(t *testing.T, declarations map[string]string) (float64, string, string) {
	t.Helper()

	widthText := declarations["outline-width"]
	style := declarations["outline-style"]
	color := declarations["outline-color"]
	if shorthand, ok := declarations["outline"]; ok {
		widthText, style, color = "", "", ""
		for _, part := range strings.Fields(shorthand) {
			switch {
			case strings.HasSuffix(part, "px"):
				widthText = part
			case part == "none" || part == "solid" || part == "auto" || part == "dashed" || part == "dotted" || part == "double" || part == "hidden":
				style = part
			default:
				color = part
			}
		}
	}
	width, ok := uiKitPixels(widthText)
	if !ok {
		t.Fatalf(".ui-btn:focus-visible has no parseable outline width (outline %q)", declarations["outline"])
	}
	return width, style, color
}

func uiKitPixels(value string) (float64, bool) {
	value = strings.TrimSpace(value)
	if !strings.HasSuffix(value, "px") {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(strings.TrimSuffix(value, "px"), 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

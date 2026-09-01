package dockerapp

import (
	"slices"
	"testing"
)

func TestSemverSelectsOfficialCandidatesDescending(t *testing.T) {
	t.Parallel()
	tags := []string{"1.27.2", "1.28.0", "2.0.0", "1.27.2-rc.1"}
	got := SelectSemverCandidates("1.27.1", tags, "")
	want := []string{"2.0.0", "1.28.0", "1.27.2"}
	if !slices.Equal(got, want) {
		t.Fatalf("candidates=%v, want %v", got, want)
	}
	if slices.Contains(got, "1.27.2-rc.1") {
		t.Fatal("prerelease 1.27.2-rc.1 must not be a candidate when the constraint has no prerelease")
	}
}

func TestSemverTildeConstraintHitsPatchOnly(t *testing.T) {
	t.Parallel()
	got := SelectSemverCandidates("1.27.1", []string{"1.27.2", "1.28.0", "2.0.0", "1.27.2-rc.1"}, "~1.27.1")
	if !slices.Equal(got, []string{"1.27.2"}) {
		t.Fatalf("tilde candidates=%v, want [1.27.2]", got)
	}
}

func TestSemverCaretConstraintHitsMinorNotMajor(t *testing.T) {
	t.Parallel()
	got := SelectSemverCandidates("1.27.1", []string{"1.27.2", "1.28.0", "2.0.0", "1.27.2-rc.1"}, "^1.27.1")
	if !slices.Equal(got, []string{"1.28.0", "1.27.2"}) {
		t.Fatalf("caret candidates=%v, want [1.28.0 1.27.2]", got)
	}
}

func TestSemverAlpineVariantDoesNotMatchPlainTag(t *testing.T) {
	t.Parallel()
	got := SelectSemverCandidates("1.27.1-alpine", []string{"1.28.0", "1.27.2", "1.27.2-alpine", "1.28.0-alpine"}, "")
	if slices.Contains(got, "1.28.0") || slices.Contains(got, "1.27.2") {
		t.Fatalf("plain tags must not be alpine candidates: %v", got)
	}
	if !slices.Equal(got, []string{"1.28.0-alpine", "1.27.2-alpine"}) {
		t.Fatalf("alpine candidates=%v, want [1.28.0-alpine 1.27.2-alpine]", got)
	}
}

func TestSemverVPrefixEqualsUnprefixed(t *testing.T) {
	t.Parallel()
	if !SemverEqual("v1.2.3", "1.2.3") {
		t.Fatal("v1.2.3 and 1.2.3 must be the same version")
	}
	cmp, ok := SemverCompare("v1.2.3", "1.2.3")
	if !ok || cmp != 0 {
		t.Fatalf("compare v1.2.3 vs 1.2.3 = %d ok=%v, want 0 true", cmp, ok)
	}
	got := SelectSemverCandidates("1.2.3", []string{"v1.2.4", "1.2.4"}, "")
	if !slices.Equal(got, []string{"v1.2.4"}) {
		t.Fatalf("v-prefix candidates=%v, want [v1.2.4]", got)
	}
}

func TestSemverSkipsPrereleaseUnlessConstraintIncludesIt(t *testing.T) {
	t.Parallel()
	tags := []string{"1.27.2", "1.27.2-rc.1", "1.27.3-rc.1"}
	if slices.Contains(SelectSemverCandidates("1.27.1", tags, "^1.27.1"), "1.27.2-rc.1") {
		t.Fatal("1.27.2-rc.1 must not be a candidate when the constraint has no prerelease")
	}
	got := SelectSemverCandidates("1.27.1", tags, "^1.27.1-rc.1")
	if !slices.Contains(got, "1.27.2-rc.1") || !slices.Contains(got, "1.27.2") {
		t.Fatalf("explicit prerelease constraint candidates=%v", got)
	}
}

func TestSemverLatestIsNotGreaterThanRelease(t *testing.T) {
	t.Parallel()
	if SemverGreater("latest", "1.27.1") {
		t.Fatal("unparseable latest must not be treated as greater than 1.27.1")
	}
	if _, _, ok := ParseSemverTag("latest"); ok {
		t.Fatal("latest must not parse as semver")
	}
	got := SelectSemverCandidates("1.27.1", []string{"latest", "stable", "main"}, "")
	if len(got) != 0 {
		t.Fatalf("floating tags as candidates=%v, want none", got)
	}
}

func TestSemverXRangeAndZeroMajorCaret(t *testing.T) {
	t.Parallel()
	xgot := SelectSemverCandidates("1.2.3", []string{"1.2.4", "1.3.0", "2.0.0"}, "1.2.x")
	if !slices.Equal(xgot, []string{"1.2.4"}) {
		t.Fatalf("1.2.x candidates=%v, want [1.2.4]", xgot)
	}
	zero := SelectSemverCandidates("0.2.3", []string{"0.2.4", "0.3.0", "1.0.0"}, "^0.2.3")
	if !slices.Equal(zero, []string{"0.2.4"}) {
		t.Fatalf("^0.2.3 candidates=%v, want [0.2.4]", zero)
	}
	if !MatchSemverConstraint("1.2.4", "1.2.x") || MatchSemverConstraint("1.3.0", "1.2.x") {
		t.Fatal("1.2.x must match 1.2.4 and not 1.3.0")
	}
	if !MatchSemverConstraint("1.28.0", "*") {
		t.Fatal("* must match a higher minor")
	}
}

func TestSemverCurrentPrereleaseIncludesNewerPrereleases(t *testing.T) {
	t.Parallel()
	got := SelectSemverCandidates("1.27.1-rc.1", []string{"1.27.1-rc.2", "1.27.1", "1.27.2-rc.1", "1.27.0"}, "")
	want := []string{"1.27.2-rc.1", "1.27.1", "1.27.1-rc.2"}
	if !slices.Equal(got, want) {
		t.Fatalf("prerelease current candidates=%v, want %v", got, want)
	}
}

func TestSemverImageRefTagIsParsed(t *testing.T) {
	t.Parallel()
	got := SelectSemverCandidates("nginx:1.27.1", []string{"nginx:1.27.2", "nginx:1.28.0-alpine"}, "")
	if !slices.Equal(got, []string{"nginx:1.27.2"}) {
		t.Fatalf("image-ref candidates=%v, want [nginx:1.27.2]", got)
	}
}

package webdav

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"os"
	"strings"
	"sync"
)

// resourceLockStripes serializes conditional mutations of one resource without
// a process-wide lock. The stripe is held from the If-Match check through the
// WebDAV handler so a second conditional write observes the first write's ETag.
const resourceLockStripes = 64

var resourceLocks [resourceLockStripes]sync.Mutex

func lockResource(target string) func() {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(target))
	mu := &resourceLocks[hash.Sum32()%resourceLockStripes]
	mu.Lock()
	return mu.Unlock
}

// resourceETag matches golang.org/x/net/webdav findETag for regular files.
// Collections do not advertise getetag, so they have no strong validator.
func resourceETag(info os.FileInfo) string {
	if info == nil || !info.Mode().IsRegular() {
		return ""
	}
	return fmt.Sprintf(`"%x%x"`, info.ModTime().UnixNano(), info.Size())
}

func ifMatchApplies(method string) bool {
	switch method {
	case http.MethodPut, http.MethodDelete, "COPY", "MOVE", "MKCOL", "PROPPATCH":
		return true
	default:
		return false
	}
}

// guardIfMatch evaluates If-Match before a state-changing WebDAV method.
// A false condition is rejected with 412 and the handler is not called.
// The returned unlock function is held by the caller until the method finishes.
func guardIfMatch(writer http.ResponseWriter, request *http.Request, root string) (func(), bool) {
	if !ifMatchApplies(request.Method) || len(request.Header.Values("If-Match")) == 0 {
		return nil, false
	}
	target, err := resolveInsideRoot(root, strings.TrimPrefix(request.URL.Path, DavPrefix))
	if err != nil {
		return nil, false
	}
	unlock := lockResource(target)
	info, err := os.Stat(target)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		unlock()
		return nil, false
	}
	exists := err == nil
	etag := ""
	if exists {
		etag = resourceETag(info)
	}
	if ifMatchAllowed(request.Header, exists, etag) {
		return unlock, false
	}
	unlock()
	writePreconditionFailed(writer, etag)
	return nil, true
}

func writePreconditionFailed(writer http.ResponseWriter, etag string) {
	if etag != "" {
		writer.Header().Set("ETag", etag)
	}
	http.Error(writer, http.StatusText(http.StatusPreconditionFailed), http.StatusPreconditionFailed)
}

// ifMatchAllowed reports whether a present If-Match header permits the method.
// An absent header is allowed. Invalid or non-matching values are rejected.
func ifMatchAllowed(header http.Header, exists bool, current string) bool {
	switch classifyIfMatch(header, current) {
	case ifMatchAbsent:
		return true
	case ifMatchWildcard:
		return exists
	case ifMatchMatched:
		return true
	default:
		return false
	}
}

type ifMatchClass int

const (
	ifMatchInvalid ifMatchClass = iota
	ifMatchAbsent
	ifMatchWildcard
	ifMatchMatched
	ifMatchUnmatched
)

func classifyIfMatch(header http.Header, current string) ifMatchClass {
	values := header.Values("If-Match")
	if len(values) == 0 {
		return ifMatchAbsent
	}
	class := ifMatchAbsent
	for _, value := range values {
		rest := value
		for {
			rest = strings.TrimLeft(rest, " \t")
			if rest == "" {
				break
			}
			if rest[0] == ',' {
				rest = rest[1:]
				continue
			}
			if rest[0] == '*' {
				if class != ifMatchAbsent {
					return ifMatchInvalid
				}
				class = ifMatchWildcard
				rest = rest[1:]
				continue
			}
			tag, next := cutEntityTag(rest)
			if tag == "" {
				return ifMatchInvalid
			}
			if class == ifMatchWildcard {
				return ifMatchInvalid
			}
			if class != ifMatchMatched {
				class = ifMatchUnmatched
			}
			if strongETagMatch(tag, current) {
				class = ifMatchMatched
			}
			rest = next
		}
	}
	if class == ifMatchAbsent {
		return ifMatchInvalid
	}
	return class
}

func strongETagMatch(candidate, current string) bool {
	return candidate == current && len(candidate) >= 2 && candidate[0] == '"' && candidate[len(candidate)-1] == '"'
}

func cutEntityTag(value string) (string, string) {
	start := value
	if strings.HasPrefix(value, "W/") {
		value = value[2:]
	}
	if value == "" || value[0] != '"' {
		return "", ""
	}
	for index := 1; index < len(value); index++ {
		char := value[index]
		if char == '"' {
			consumed := len(start) - len(value) + index + 1
			return start[:consumed], value[index+1:]
		}
		if char == 0x21 || (char >= 0x23 && char <= 0x7E) || char >= 0x80 {
			continue
		}
		return "", ""
	}
	return "", ""
}

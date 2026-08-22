package webdav

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const maxUploadMemory = 32 << 20

type apiError struct {
	Error string `json:"error"`
}

type listEntry struct {
	Name string `json:"name"`
	Dir  bool   `json:"dir"`
	Size int64  `json:"size,omitempty"`
}

type listResponse struct {
	Path    string      `json:"path"`
	Entries []listEntry `json:"entries"`
}

type pathRequest struct {
	Path string `json:"path"`
}

type renameRequest struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func (handler *Handler) serveAPI(writer http.ResponseWriter, request *http.Request) {
	pluginsdk.SetPluginUIResponseHeaders(writer.Header())
	switch request.URL.Path {
	case "/api/list":
		handler.apiList(writer, request)
	case "/api/download":
		handler.apiDownload(writer, request)
	case "/api/upload":
		handler.apiUpload(writer, request)
	case "/api/mkdir":
		handler.apiMkdir(writer, request)
	case "/api/rename":
		handler.apiRename(writer, request)
	case "/api/delete":
		handler.apiDelete(writer, request)
	default:
		http.NotFound(writer, request)
	}
}

func (handler *Handler) apiList(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writeMethodNotAllowed(writer, "GET, HEAD")
		return
	}
	target, err := handler.queryPath(request, true)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, err)
		return
	}
	info, err := os.Stat(target)
	if err != nil {
		writeAPIError(writer, http.StatusNotFound, errors.New("path is not found"))
		return
	}
	if !info.IsDir() {
		writeAPIError(writer, http.StatusBadRequest, errors.New("path is not a directory"))
		return
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, errors.New("directory cannot be listed"))
		return
	}
	listed := make([]listEntry, 0, len(entries))
	for _, entry := range entries {
		item := listEntry{Name: entry.Name(), Dir: entry.IsDir()}
		if info, err := entry.Info(); err == nil && !entry.IsDir() {
			item.Size = info.Size()
		}
		listed = append(listed, item)
	}
	sort.Slice(listed, func(i, j int) bool {
		if listed[i].Dir != listed[j].Dir {
			return listed[i].Dir
		}
		return listed[i].Name < listed[j].Name
	})
	_ = pluginsdk.WritePluginUIJSON(writer, http.StatusOK, listResponse{Path: virtualPath(handler.root, target), Entries: listed})
}

func (handler *Handler) apiDownload(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writeMethodNotAllowed(writer, "GET, HEAD")
		return
	}
	target, err := handler.queryPath(request, false)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, err)
		return
	}
	info, err := os.Stat(target)
	if err != nil {
		writeAPIError(writer, http.StatusNotFound, errors.New("path is not found"))
		return
	}
	if info.IsDir() {
		writeAPIError(writer, http.StatusBadRequest, errors.New("path is a directory"))
		return
	}
	file, err := os.Open(target)
	if err != nil {
		writeAPIError(writer, http.StatusNotFound, errors.New("path is not found"))
		return
	}
	defer file.Close()
	writer.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(filepath.Base(target), `"`, "")+`"`)
	http.ServeContent(writer, request, filepath.Base(target), info.ModTime(), file)
}

func (handler *Handler) apiUpload(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeMethodNotAllowed(writer, "POST")
		return
	}
	if err := request.ParseMultipartForm(maxUploadMemory); err != nil {
		writeAPIError(writer, http.StatusBadRequest, errors.New("upload is invalid"))
		return
	}
	file, header, err := request.FormFile("file")
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, errors.New("upload is invalid"))
		return
	}
	defer file.Close()
	name := path.Base(strings.ReplaceAll(header.Filename, `\`, "/"))
	if name == "" || name == "." || name == ".." {
		writeAPIError(writer, http.StatusBadRequest, errors.New("upload name is invalid"))
		return
	}
	dir := strings.TrimSpace(request.FormValue("path"))
	if dir == "" {
		dir = "/"
	}
	target, err := resolveInsideRoot(handler.root, path.Join(strings.TrimPrefix(dir, "/"), name))
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, err)
		return
	}
	if err := writeFile(target, file); err != nil {
		writeAPIError(writer, http.StatusBadRequest, err)
		return
	}
	_ = pluginsdk.WritePluginUIJSON(writer, http.StatusCreated, map[string]string{"path": virtualPath(handler.root, target)})
}

func (handler *Handler) apiMkdir(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeMethodNotAllowed(writer, "POST")
		return
	}
	var body pathRequest
	if err := decodeAPIBody(request, &body); err != nil || strings.TrimSpace(body.Path) == "" {
		writeAPIError(writer, http.StatusBadRequest, errors.New("path is invalid"))
		return
	}
	target, err := resolveInsideRoot(handler.root, body.Path)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, err)
		return
	}
	if target == handler.root {
		writeAPIError(writer, http.StatusBadRequest, errors.New("path is invalid"))
		return
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		writeAPIError(writer, http.StatusBadRequest, errors.New("directory cannot be created"))
		return
	}
	_ = pluginsdk.WritePluginUIJSON(writer, http.StatusCreated, map[string]string{"path": virtualPath(handler.root, target)})
}

func (handler *Handler) apiRename(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeMethodNotAllowed(writer, "POST")
		return
	}
	var body renameRequest
	if err := decodeAPIBody(request, &body); err != nil || strings.TrimSpace(body.From) == "" || strings.TrimSpace(body.To) == "" {
		writeAPIError(writer, http.StatusBadRequest, errors.New("rename is invalid"))
		return
	}
	from, err := resolveInsideRoot(handler.root, body.From)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, err)
		return
	}
	to, err := resolveInsideRoot(handler.root, body.To)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, err)
		return
	}
	if from == handler.root || to == handler.root {
		writeAPIError(writer, http.StatusBadRequest, errors.New("rename is invalid"))
		return
	}
	if err := os.Rename(from, to); err != nil {
		writeAPIError(writer, http.StatusBadRequest, errors.New("rename failed"))
		return
	}
	_ = pluginsdk.WritePluginUIJSON(writer, http.StatusOK, map[string]string{"path": virtualPath(handler.root, to)})
}

func (handler *Handler) apiDelete(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeMethodNotAllowed(writer, "POST")
		return
	}
	var body pathRequest
	if err := decodeAPIBody(request, &body); err != nil || strings.TrimSpace(body.Path) == "" {
		writeAPIError(writer, http.StatusBadRequest, errors.New("path is invalid"))
		return
	}
	target, err := resolveInsideRoot(handler.root, body.Path)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, err)
		return
	}
	if target == handler.root {
		writeAPIError(writer, http.StatusBadRequest, errors.New("path is invalid"))
		return
	}
	if _, err := os.Stat(target); err != nil {
		writeAPIError(writer, http.StatusNotFound, errors.New("path is not found"))
		return
	}
	if err := os.RemoveAll(target); err != nil {
		writeAPIError(writer, http.StatusBadRequest, errors.New("delete failed"))
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) queryPath(request *http.Request, allowRoot bool) (string, error) {
	value := request.URL.Query().Get("path")
	if strings.TrimSpace(value) == "" {
		value = "/"
	}
	target, err := resolveInsideRoot(handler.root, value)
	if err != nil {
		return "", err
	}
	if !allowRoot && target == handler.root {
		return "", errPathEscape
	}
	return target, nil
}

func writeFile(target string, source io.Reader) error {
	file, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("file cannot be written")
	}
	defer file.Close()
	if _, err := io.Copy(file, source); err != nil {
		return errors.New("file cannot be written")
	}
	return nil
}

func decodeAPIBody(request *http.Request, dest any) error {
	decoder := json.NewDecoder(io.LimitReader(request.Body, MaxConfigBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one object")
	}
	return nil
}

func writeAPIError(writer http.ResponseWriter, status int, err error) {
	message := "request is invalid"
	if err != nil {
		if errors.Is(err, errPathEscape) {
			message = "path is outside the share root"
		} else {
			message = err.Error()
		}
	}
	_ = pluginsdk.WritePluginUIJSON(writer, status, apiError{Error: message})
}

func writeMethodNotAllowed(writer http.ResponseWriter, allow string) {
	writer.Header().Set("Allow", allow)
	http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
}

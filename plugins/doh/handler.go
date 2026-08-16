package doh

import (
	"errors"
	"io"
	"net/http"
)

func (service *Service) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != DNSQueryPath {
		http.NotFound(writer, request)
		return
	}
	body, err := readDNSBody(request)
	if err != nil {
		writeDoHError(writer, err)
		return
	}
	response, err := service.Serve(request.Context(), HTTPRequest{
		Method:      request.Method,
		Query:       request.URL.RawQuery,
		ContentType: request.Header.Get("Content-Type"),
		Accept:      request.Header.Get("Accept"),
		Forwarded:   singleForwarded(request.Header.Values("Forwarded")),
		Body:        body,
	})
	if err != nil {
		writeDoHError(writer, err)
		return
	}
	writer.Header().Set("Content-Type", response.ContentType)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(response.Body)
}

func readDNSBody(request *http.Request) ([]byte, error) {
	if request.Body == nil {
		return nil, nil
	}
	defer request.Body.Close()
	body, err := io.ReadAll(io.LimitReader(request.Body, int64(MaxDNSRequestBytes)+1))
	if err != nil {
		return nil, ErrInvalidRequest
	}
	if len(body) > MaxDNSRequestBytes {
		return nil, ErrRequestTooLarge
	}
	return body, nil
}

func singleForwarded(values []string) string {
	if len(values) != 1 {
		return ""
	}
	return values[0]
}

func writeDoHError(writer http.ResponseWriter, err error) {
	http.Error(writer, http.StatusText(dohStatus(err)), dohStatus(err))
}

func dohStatus(err error) int {
	switch {
	case errors.Is(err, ErrUnsupportedMediaType):
		return http.StatusUnsupportedMediaType
	case errors.Is(err, ErrRequestTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrInvalidDNSMessage):
		return http.StatusBadRequest
	case errors.Is(err, ErrConcurrencyExhausted), errors.Is(err, ErrRevoked), errors.Is(err, ErrCacheUnavailable), errors.Is(err, ErrClockUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrNoHealthyUpstream), errors.Is(err, ErrUpstreamFailed), errors.Is(err, ErrResponseMismatch), errors.Is(err, ErrResponseTooLarge):
		return http.StatusBadGateway
	default:
		return http.StatusBadGateway
	}
}

package shadowsocksserver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	maxSniffBytes = 16 << 10
	sniffTimeout  = 250 * time.Millisecond
)

type sniffState uint8

const (
	sniffNeedMore sniffState = iota
	sniffDone
)

func sniffTCPDomain(payload []byte) (string, sniffState) {
	if len(payload) == 0 {
		return "", sniffNeedMore
	}
	if len(payload) > maxSniffBytes {
		return "", sniffDone
	}
	if strings.HasPrefix(string(payload), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
		return "", sniffDone
	}
	if payload[0] == 0x16 {
		return sniffTLSServerName(payload)
	}
	return sniffHTTPHost(payload)
}

func sniffHTTPHost(payload []byte) (string, sniffState) {
	text := string(payload)
	for index, value := range payload {
		if value == '\n' && (index == 0 || payload[index-1] != '\r') {
			return "", sniffDone
		}
		if value == 0x7f || value < 0x20 && value != '\r' && value != '\n' {
			return "", sniffDone
		}
	}
	end := strings.Index(text, "\r\n\r\n")
	if end < 0 {
		if strings.ContainsRune(text, '\x00') || len(payload) == maxSniffBytes {
			return "", sniffDone
		}
		return "", sniffNeedMore
	}
	lines := strings.Split(text[:end], "\r\n")
	requestParts := strings.Fields(lines[0])
	if len(lines) < 2 || len(requestParts) != 3 || (requestParts[2] != "HTTP/1.0" && requestParts[2] != "HTTP/1.1") {
		return "", sniffDone
	}
	host := ""
	if strings.HasPrefix(requestParts[1], "http://") || strings.HasPrefix(requestParts[1], "https://") {
		parsed, err := url.Parse(requestParts[1])
		if err != nil || parsed.User != nil {
			return "", sniffDone
		}
		var ok bool
		host, ok = canonicalSniffHost(parsed.Host)
		if !ok {
			return "", sniffDone
		}
	}
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			return "", sniffDone
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return "", sniffDone
		}
		if !strings.EqualFold(strings.TrimSpace(name), "host") {
			continue
		}
		candidate, ok := canonicalSniffHost(strings.TrimSpace(value))
		if !ok {
			return "", sniffDone
		}
		if host != "" && host != candidate {
			return "", sniffDone
		}
		host = candidate
	}
	return host, sniffDone
}

func canonicalSniffHost(value string) (string, bool) {
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = strings.Trim(host, "[]")
	}
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	if value == "" || len(value) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return "", false
			}
		}
	}
	return value, true
}

func sniffTLSServerName(payload []byte) (string, sniffState) {
	handshake := make([]byte, 0, len(payload))
	position := 0
	for position < len(payload) {
		if len(payload)-position < 5 {
			return "", sniffNeedMore
		}
		if payload[position] != 0x16 || payload[position+1] != 3 || payload[position+2] > 3 {
			return "", sniffDone
		}
		length := int(binary.BigEndian.Uint16(payload[position+3 : position+5]))
		if length < 1 || length > maxSniffBytes || position+5+length > len(payload) {
			return "", sniffNeedMore
		}
		handshake = append(handshake, payload[position+5:position+5+length]...)
		position += 5 + length
		if len(handshake) >= 4 {
			wanted := 4 + (int(handshake[1]) << 16) + (int(handshake[2]) << 8) + int(handshake[3])
			if len(handshake) >= wanted {
				return parseClientHello(handshake[:wanted]), sniffDone
			}
		}
	}
	return "", sniffNeedMore
}

func parseClientHello(handshake []byte) string {
	if len(handshake) < 4+2+32+1 || handshake[0] != 1 {
		return ""
	}
	body := handshake[4:]
	if body[0] != 3 || body[1] != 3 {
		return ""
	}
	position := 34
	if position >= len(body) {
		return ""
	}
	position += 1 + int(body[position])
	if position+2 > len(body) {
		return ""
	}
	ciphers := int(binary.BigEndian.Uint16(body[position : position+2]))
	position += 2 + ciphers
	if position >= len(body) {
		return ""
	}
	position += 1 + int(body[position])
	if position+2 > len(body) {
		return ""
	}
	extensionsLength := int(binary.BigEndian.Uint16(body[position : position+2]))
	position += 2
	if extensionsLength < 0 || position+extensionsLength != len(body) {
		return ""
	}
	host := ""
	for position < len(body) {
		if position+4 > len(body) {
			return ""
		}
		typeID := binary.BigEndian.Uint16(body[position : position+2])
		length := int(binary.BigEndian.Uint16(body[position+2 : position+4]))
		position += 4
		if position+length > len(body) {
			return ""
		}
		extension := body[position : position+length]
		position += length
		if typeID == 0xfe0d {
			return ""
		}
		if typeID != 0 {
			continue
		}
		if len(extension) < 2 || int(binary.BigEndian.Uint16(extension[:2])) != len(extension)-2 {
			return ""
		}
		cursor := 2
		for cursor < len(extension) {
			if cursor+3 > len(extension) {
				return ""
			}
			nameType := extension[cursor]
			nameLength := int(binary.BigEndian.Uint16(extension[cursor+1 : cursor+3]))
			cursor += 3
			if cursor+nameLength > len(extension) || nameType != 0 {
				return ""
			}
			candidate, ok := canonicalSniffHost(string(extension[cursor : cursor+nameLength]))
			cursor += nameLength
			if !ok || host != "" && host != candidate {
				return ""
			}
			host = candidate
		}
	}
	return host
}

var errSniffLimit = errors.New("sniff chunk exceeds remaining budget")

func transactionalSniffChunk(conn net.Conn, session *TCPServerSession, remaining int) ([]byte, []byte, error) {
	if conn == nil || session == nil || remaining < 1 {
		return nil, nil, ErrRevoked
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.inbound == nil {
		return nil, nil, ErrRevoked
	}
	trial := *session.inbound
	header := make([]byte, 2+trial.aead.Overhead())
	n, err := io.ReadFull(conn, header)
	replayed := append([]byte(nil), header[:n]...)
	if err != nil {
		return nil, replayed, err
	}
	plain, err := trial.open(header)
	if err != nil || len(plain) != 2 {
		return nil, replayed, ErrAuthentication
	}
	length := int(binary.BigEndian.Uint16(plain))
	maximum := maxLegacyPayload
	if session.modern {
		maximum = max2022Payload
	}
	if length < 1 || length > maximum {
		return nil, replayed, ErrProtocol
	}
	if length > remaining {
		return nil, replayed, errSniffLimit
	}
	body := make([]byte, length+trial.aead.Overhead())
	n, err = io.ReadFull(conn, body)
	replayed = append(replayed, body[:n]...)
	if err != nil {
		return nil, replayed, err
	}
	payload, err := trial.open(body)
	if err != nil {
		return nil, replayed, ErrAuthentication
	}
	session.inbound.nonce = trial.nonce
	return payload, nil, nil
}

func sniffTargetDomain(ctx context.Context, conn net.Conn, session *TCPServerSession, initial []byte, outerDeadline time.Time) (net.Conn, string, []byte) {
	buffer := append([]byte(nil), initial...)
	if len(buffer) > maxSniffBytes {
		return conn, "", buffer
	}
	deadline := time.Now().Add(sniffTimeout)
	if !outerDeadline.IsZero() && outerDeadline.Before(deadline) {
		deadline = outerDeadline
	}
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(outerDeadline)
	for {
		domain, state := sniffTCPDomain(buffer)
		if state == sniffDone {
			return conn, domain, buffer
		}
		if len(buffer) >= maxSniffBytes {
			return conn, "", buffer
		}
		chunk, ciphertext, err := transactionalSniffChunk(conn, session, maxSniffBytes-len(buffer))
		if len(ciphertext) > 0 {
			conn = &prefixConn{Conn: conn, prefix: ciphertext}
		}
		if err != nil {
			return conn, "", buffer
		}
		buffer = append(buffer, chunk...)
	}
}

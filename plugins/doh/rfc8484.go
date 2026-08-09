package doh

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

const dnsMediaType = "application/dns-message"

type parsedQuery struct {
	wire, normalized, question []byte
	key, digest, qtype         string
	id                         uint16
}

func parseHTTPRequest(request HTTPRequest) (parsedQuery, error) {
	if request.Accept != dnsMediaType {
		return parsedQuery{}, ErrUnsupportedMediaType
	}
	var wire []byte
	switch request.Method {
	case "GET":
		if request.ContentType != "" || len(request.Body) != 0 || !strings.HasPrefix(request.Query, "dns=") || strings.Contains(request.Query, "&") || len(request.Query) == 4 {
			return parsedQuery{}, ErrInvalidRequest
		}
		encoded := strings.TrimPrefix(request.Query, "dns=")
		if strings.Contains(encoded, "=") {
			return parsedQuery{}, ErrInvalidRequest
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return parsedQuery{}, ErrInvalidRequest
		}
		wire = decoded
	case "POST":
		if request.Query != "" || request.ContentType != dnsMediaType {
			return parsedQuery{}, ErrUnsupportedMediaType
		}
		wire = append([]byte(nil), request.Body...)
	default:
		return parsedQuery{}, ErrInvalidRequest
	}
	if len(wire) > MaxDNSRequestBytes {
		return parsedQuery{}, ErrRequestTooLarge
	}
	return parseDNSQuery(wire)
}

func parseDNSQuery(wire []byte) (parsedQuery, error) {
	if len(wire) < 17 {
		return parsedQuery{}, ErrInvalidDNSMessage
	}
	flags := binary.BigEndian.Uint16(wire[2:4])
	if flags&0x8000 != 0 || flags&0x7800 != 0 || binary.BigEndian.Uint16(wire[4:6]) != 1 || binary.BigEndian.Uint16(wire[6:8]) != 0 || binary.BigEndian.Uint16(wire[8:10]) != 0 || binary.BigEndian.Uint16(wire[10:12]) != 0 {
		return parsedQuery{}, ErrInvalidDNSMessage
	}
	questionEnd, canonicalName, err := parseQuestionName(wire, 12)
	if err != nil || questionEnd+4 != len(wire) {
		return parsedQuery{}, ErrInvalidDNSMessage
	}
	qtype := binary.BigEndian.Uint16(wire[questionEnd : questionEnd+2])
	qclass := binary.BigEndian.Uint16(wire[questionEnd+2 : questionEnd+4])
	if qtype == 0 || qclass != 1 {
		return parsedQuery{}, ErrInvalidDNSMessage
	}
	normalized := append([]byte(nil), wire...)
	normalized[0], normalized[1] = 0, 0
	copy(normalized[12:questionEnd], canonicalName)
	digest := sha256.Sum256(normalized)
	question := append([]byte(nil), normalized[12:]...)
	return parsedQuery{wire: append([]byte(nil), wire...), normalized: normalized, question: question, key: hex.EncodeToString(digest[:]), digest: hex.EncodeToString(digest[:8]), qtype: strconv.Itoa(int(qtype)), id: binary.BigEndian.Uint16(wire[:2])}, nil
}

func parseQuestionName(wire []byte, offset int) (int, []byte, error) {
	canonical := make([]byte, 0, 255)
	for labels := 0; labels <= 127; labels++ {
		if offset >= len(wire) {
			return 0, nil, ErrInvalidDNSMessage
		}
		length := int(wire[offset])
		if length&0xc0 != 0 || length > 63 {
			return 0, nil, ErrInvalidDNSMessage
		}
		canonical = append(canonical, byte(length))
		offset++
		if length == 0 {
			if len(canonical) > 255 {
				return 0, nil, ErrInvalidDNSMessage
			}
			return offset, canonical, nil
		}
		if offset+length > len(wire) || len(canonical)+length > 255 {
			return 0, nil, ErrInvalidDNSMessage
		}
		for _, current := range wire[offset : offset+length] {
			if current >= 'A' && current <= 'Z' {
				current += 'a' - 'A'
			}
			canonical = append(canonical, current)
		}
		offset += length
	}
	return 0, nil, ErrInvalidDNSMessage
}

type responseMetadata struct {
	ttl       uint32
	cacheable bool
	negative  bool
}

func validateDNSResponse(query parsedQuery, wire []byte) (responseMetadata, []byte, error) {
	if len(wire) > MaxDNSResponseBytes {
		return responseMetadata{}, nil, ErrResponseTooLarge
	}
	if len(wire) < 17 || binary.BigEndian.Uint16(wire[:2]) != query.id {
		return responseMetadata{}, nil, ErrResponseMismatch
	}
	flags := binary.BigEndian.Uint16(wire[2:4])
	if flags&0x8000 == 0 || flags&0x7800 != 0 || binary.BigEndian.Uint16(wire[4:6]) != 1 {
		return responseMetadata{}, nil, ErrInvalidDNSMessage
	}
	questionEnd, canonicalName, err := parseQuestionName(wire, 12)
	if err != nil || questionEnd+4 > len(wire) {
		return responseMetadata{}, nil, ErrInvalidDNSMessage
	}
	question := append(canonicalName, wire[questionEnd:questionEnd+4]...)
	if string(question) != string(query.question) {
		return responseMetadata{}, nil, ErrResponseMismatch
	}
	offset := questionEnd + 4
	answerCount := int(binary.BigEndian.Uint16(wire[6:8]))
	authorityCount := int(binary.BigEndian.Uint16(wire[8:10]))
	additionalCount := int(binary.BigEndian.Uint16(wire[10:12]))
	minAnswerTTL, minNegativeTTL := uint32(0), uint32(0)
	for index := 0; index < answerCount+authorityCount+additionalCount; index++ {
		var next int
		next, err = skipDNSName(wire, offset)
		if err != nil || next+10 > len(wire) {
			return responseMetadata{}, nil, ErrInvalidDNSMessage
		}
		rrType := binary.BigEndian.Uint16(wire[next : next+2])
		ttl := binary.BigEndian.Uint32(wire[next+4 : next+8])
		rdLength := int(binary.BigEndian.Uint16(wire[next+8 : next+10]))
		rdataEnd := next + 10 + rdLength
		if rdataEnd > len(wire) {
			return responseMetadata{}, nil, ErrInvalidDNSMessage
		}
		if index < answerCount && (minAnswerTTL == 0 || ttl < minAnswerTTL) {
			minAnswerTTL = ttl
		}
		if index >= answerCount && index < answerCount+authorityCount && rrType == 6 && rdLength >= 20 {
			minimum := binary.BigEndian.Uint32(wire[rdataEnd-4 : rdataEnd])
			if minimum < ttl {
				ttl = minimum
			}
			if minNegativeTTL == 0 || ttl < minNegativeTTL {
				minNegativeTTL = ttl
			}
		}
		offset = rdataEnd
	}
	if offset != len(wire) {
		return responseMetadata{}, nil, ErrInvalidDNSMessage
	}
	rcode := flags & 0x000f
	metadata := responseMetadata{}
	switch {
	case rcode == 0 && answerCount > 0:
		metadata.ttl, metadata.cacheable = minAnswerTTL, minAnswerTTL > 0
	case (rcode == 0 && answerCount == 0) || rcode == 3:
		if minNegativeTTL == 0 {
			return responseMetadata{}, nil, ErrInvalidDNSMessage
		}
		metadata.ttl, metadata.cacheable, metadata.negative = minNegativeTTL, true, true
	default:
		return responseMetadata{}, nil, ErrUpstreamFailed
	}
	normalized := append([]byte(nil), wire...)
	normalized[0], normalized[1] = 0, 0
	return metadata, normalized, nil
}

func skipDNSName(wire []byte, offset int) (int, error) {
	for labels := 0; labels <= 127; labels++ {
		if offset >= len(wire) {
			return 0, ErrInvalidDNSMessage
		}
		length := int(wire[offset])
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(wire) {
				return 0, ErrInvalidDNSMessage
			}
			pointer := int(binary.BigEndian.Uint16(wire[offset:offset+2]) & 0x3fff)
			if pointer >= len(wire) {
				return 0, ErrInvalidDNSMessage
			}
			return offset + 2, nil
		}
		if length&0xc0 != 0 || length > 63 || offset+1+length > len(wire) {
			return 0, ErrInvalidDNSMessage
		}
		offset++
		if length == 0 {
			return offset, nil
		}
		offset += length
	}
	return 0, ErrInvalidDNSMessage
}

func responseWithID(normalized []byte, id uint16) []byte {
	result := append([]byte(nil), normalized...)
	binary.BigEndian.PutUint16(result[:2], id)
	return result
}

package doh

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"mime"
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
	if !acceptsDNSMessage(request.Accept) {
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
		mediaType, parameters, err := mime.ParseMediaType(request.ContentType)
		if request.Query != "" || err != nil || !strings.EqualFold(mediaType, dnsMediaType) || len(parameters) != 0 {
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

func acceptsDNSMessage(value string) bool {
	if strings.TrimSpace(value) == "" {
		return true
	}
	ranges, ok := splitHTTPList(value)
	if !ok {
		return false
	}
	for _, current := range ranges {
		mediaType, parameters, err := mime.ParseMediaType(current)
		if err != nil {
			return false
		}
		quality := 1.0
		if raw, exists := parameters["q"]; exists {
			quality, err = strconv.ParseFloat(raw, 64)
			if err != nil || quality < 0 || quality > 1 {
				return false
			}
		}
		if quality > 0 && (strings.EqualFold(mediaType, dnsMediaType) || mediaType == "application/*" || mediaType == "*/*") {
			return true
		}
	}
	return false
}

func splitHTTPList(value string) ([]string, bool) {
	if len(value) > 4096 {
		return nil, false
	}
	var result []string
	start, quoted, escaped := 0, false, false
	for index, current := range value {
		switch {
		case escaped:
			escaped = false
		case quoted && current == '\\':
			escaped = true
		case current == '"':
			quoted = !quoted
		case current == ',' && !quoted:
			part := strings.TrimSpace(value[start:index])
			if part == "" {
				return nil, false
			}
			result = append(result, part)
			start = index + 1
		}
	}
	part := strings.TrimSpace(value[start:])
	if quoted || escaped || part == "" {
		return nil, false
	}
	return append(result, part), true
}

func parseDNSQuery(wire []byte) (parsedQuery, error) {
	if len(wire) < 17 {
		return parsedQuery{}, ErrInvalidDNSMessage
	}
	flags := binary.BigEndian.Uint16(wire[2:4])
	additionalCount := binary.BigEndian.Uint16(wire[10:12])
	if flags&0x8000 != 0 || flags&0x7800 != 0 || binary.BigEndian.Uint16(wire[4:6]) != 1 || binary.BigEndian.Uint16(wire[6:8]) != 0 || binary.BigEndian.Uint16(wire[8:10]) != 0 || additionalCount > 1 {
		return parsedQuery{}, ErrInvalidDNSMessage
	}
	questionEnd, canonicalName, err := parseQuestionName(wire, 12)
	if err != nil || questionEnd+4 > len(wire) {
		return parsedQuery{}, ErrInvalidDNSMessage
	}
	qtype := binary.BigEndian.Uint16(wire[questionEnd : questionEnd+2])
	qclass := binary.BigEndian.Uint16(wire[questionEnd+2 : questionEnd+4])
	if qtype == 0 || qclass != 1 {
		return parsedQuery{}, ErrInvalidDNSMessage
	}
	if additionalCount == 0 && questionEnd+4 != len(wire) {
		return parsedQuery{}, ErrInvalidDNSMessage
	}
	if additionalCount == 1 {
		if err := validateEDNSQuery(wire, questionEnd+4); err != nil {
			return parsedQuery{}, err
		}
	}
	normalized := append([]byte(nil), wire...)
	normalized[0], normalized[1] = 0, 0
	copy(normalized[12:questionEnd], canonicalName)
	digest := sha256.Sum256(normalized)
	question := append([]byte(nil), normalized[12:questionEnd+4]...)
	return parsedQuery{wire: append([]byte(nil), wire...), normalized: normalized, question: question, key: hex.EncodeToString(digest[:]), digest: hex.EncodeToString(digest[:8]), qtype: strconv.Itoa(int(qtype)), id: binary.BigEndian.Uint16(wire[:2])}, nil
}

func validateEDNSQuery(wire []byte, offset int) error {
	if offset+11 > len(wire) || wire[offset] != 0 {
		return ErrInvalidDNSMessage
	}
	next := offset + 1
	if binary.BigEndian.Uint16(wire[next:next+2]) != 41 {
		return ErrInvalidDNSMessage
	}
	flags := binary.BigEndian.Uint32(wire[next+4 : next+8])
	if flags&0xffff7fff != 0 {
		return ErrInvalidDNSMessage
	}
	rdataLength := int(binary.BigEndian.Uint16(wire[next+8 : next+10]))
	rdataStart, rdataEnd := next+10, next+10+rdataLength
	if rdataEnd != len(wire) {
		return ErrInvalidDNSMessage
	}
	for rdataStart < rdataEnd {
		if rdataStart+4 > rdataEnd {
			return ErrInvalidDNSMessage
		}
		optionLength := int(binary.BigEndian.Uint16(wire[rdataStart+2 : rdataStart+4]))
		rdataStart += 4
		if rdataStart+optionLength > rdataEnd {
			return ErrInvalidDNSMessage
		}
		rdataStart += optionLength
	}
	return nil
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
	var minAnswerTTL, minNegativeTTL uint32
	answerSeen, negativeSOASeen := false, false
	for index := 0; index < answerCount+authorityCount+additionalCount; index++ {
		record, recordErr := parseResourceRecord(wire, offset)
		if recordErr != nil {
			return responseMetadata{}, nil, ErrInvalidDNSMessage
		}
		if index < answerCount+authorityCount && record.class != 1 {
			return responseMetadata{}, nil, ErrInvalidDNSMessage
		}
		if index < answerCount && (!answerSeen || record.ttl < minAnswerTTL) {
			minAnswerTTL = record.ttl
			answerSeen = true
		}
		if index >= answerCount && index < answerCount+authorityCount && record.rrType == 6 {
			minimum, soaErr := parseSOAMinimum(wire, record.rdataStart, record.rdataEnd)
			if soaErr != nil {
				return responseMetadata{}, nil, ErrInvalidDNSMessage
			}
			negativeTTL := record.ttl
			if minimum < negativeTTL {
				negativeTTL = minimum
			}
			if !negativeSOASeen || negativeTTL < minNegativeTTL {
				minNegativeTTL = negativeTTL
			}
			negativeSOASeen = true
		}
		offset = record.rdataEnd
	}
	if offset != len(wire) {
		return responseMetadata{}, nil, ErrInvalidDNSMessage
	}
	rcode := flags & 0x000f
	metadata := responseMetadata{}
	switch {
	case rcode == 0 && answerCount > 0:
		if !answerSeen {
			return responseMetadata{}, nil, ErrInvalidDNSMessage
		}
		metadata.ttl, metadata.cacheable = minAnswerTTL, minAnswerTTL > 0
	case (rcode == 0 && answerCount == 0) || rcode == 3:
		if !negativeSOASeen {
			return responseMetadata{}, nil, ErrInvalidDNSMessage
		}
		metadata.ttl, metadata.cacheable, metadata.negative = minNegativeTTL, minNegativeTTL > 0, true
	default:
		return responseMetadata{}, nil, ErrUpstreamFailed
	}
	normalized := append([]byte(nil), wire...)
	normalized[0], normalized[1] = 0, 0
	return metadata, normalized, nil
}

type resourceRecord struct {
	rrType, class        uint16
	ttl                  uint32
	ttlOffset            int
	rdataStart, rdataEnd int
}

func parseResourceRecord(wire []byte, offset int) (resourceRecord, error) {
	next, err := skipDNSName(wire, offset)
	if err != nil || next+10 > len(wire) {
		return resourceRecord{}, ErrInvalidDNSMessage
	}
	rdataLength := int(binary.BigEndian.Uint16(wire[next+8 : next+10]))
	rdataStart, rdataEnd := next+10, next+10+rdataLength
	if rdataEnd > len(wire) {
		return resourceRecord{}, ErrInvalidDNSMessage
	}
	return resourceRecord{
		rrType:     binary.BigEndian.Uint16(wire[next : next+2]),
		class:      binary.BigEndian.Uint16(wire[next+2 : next+4]),
		ttl:        binary.BigEndian.Uint32(wire[next+4 : next+8]),
		ttlOffset:  next + 4,
		rdataStart: rdataStart,
		rdataEnd:   rdataEnd,
	}, nil
}

func clampDNSResponseTTLs(wire []byte, limit uint32) ([]byte, error) {
	if len(wire) < 17 {
		return nil, ErrInvalidDNSMessage
	}
	questionEnd, _, err := parseQuestionName(wire, 12)
	if err != nil || questionEnd+4 > len(wire) {
		return nil, ErrInvalidDNSMessage
	}
	answerCount := int(binary.BigEndian.Uint16(wire[6:8]))
	authorityCount := int(binary.BigEndian.Uint16(wire[8:10]))
	additionalCount := int(binary.BigEndian.Uint16(wire[10:12]))
	result := append([]byte(nil), wire...)
	offset := questionEnd + 4
	for index := 0; index < answerCount+authorityCount+additionalCount; index++ {
		record, recordErr := parseResourceRecord(result, offset)
		if recordErr != nil {
			return nil, recordErr
		}
		if record.rrType != 41 && record.ttl > limit {
			binary.BigEndian.PutUint32(result[record.ttlOffset:record.ttlOffset+4], limit)
		}
		if index >= answerCount && index < answerCount+authorityCount && record.rrType == 6 {
			minimum, soaErr := parseSOAMinimum(result, record.rdataStart, record.rdataEnd)
			if soaErr != nil {
				return nil, soaErr
			}
			if minimum > limit {
				binary.BigEndian.PutUint32(result[record.rdataEnd-4:record.rdataEnd], limit)
			}
		}
		offset = record.rdataEnd
	}
	if offset != len(result) {
		return nil, ErrInvalidDNSMessage
	}
	return result, nil
}

func parseSOAMinimum(wire []byte, start, end int) (uint32, error) {
	if start < 0 || end > len(wire) || start >= end {
		return 0, ErrInvalidDNSMessage
	}
	next, err := skipDNSName(wire, start)
	if err != nil || next > end {
		return 0, ErrInvalidDNSMessage
	}
	next, err = skipDNSName(wire, next)
	if err != nil || next+20 != end {
		return 0, ErrInvalidDNSMessage
	}
	return binary.BigEndian.Uint32(wire[end-4 : end]), nil
}

func skipDNSName(wire []byte, offset int) (int, error) {
	consumedEnd, expandedLength := -1, 0
	visited := make(map[int]struct{}, 4)
	for labels := 0; labels <= 127; labels++ {
		if offset < 12 || offset >= len(wire) {
			return 0, ErrInvalidDNSMessage
		}
		if _, exists := visited[offset]; exists {
			return 0, ErrInvalidDNSMessage
		}
		visited[offset] = struct{}{}
		length := int(wire[offset])
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(wire) {
				return 0, ErrInvalidDNSMessage
			}
			pointer := int(binary.BigEndian.Uint16(wire[offset:offset+2]) & 0x3fff)
			if pointer < 12 || pointer >= offset {
				return 0, ErrInvalidDNSMessage
			}
			if consumedEnd < 0 {
				consumedEnd = offset + 2
			}
			offset = pointer
			continue
		}
		if length&0xc0 != 0 || length > 63 || offset+1+length > len(wire) {
			return 0, ErrInvalidDNSMessage
		}
		expandedLength += length + 1
		if expandedLength > 255 {
			return 0, ErrInvalidDNSMessage
		}
		offset++
		if length == 0 {
			if consumedEnd >= 0 {
				return consumedEnd, nil
			}
			return offset, nil
		}
		offset += length
	}
	return 0, ErrInvalidDNSMessage
}

func responseWithID(normalized []byte, id uint16) []byte {
	if len(normalized) < 2 {
		return nil
	}
	result := append([]byte(nil), normalized...)
	binary.BigEndian.PutUint16(result[:2], id)
	return result
}

package upstream

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

var errDNSWire = errors.New("invalid DNS wire response")

const maxDNSCNAMEHops = 16

// WireResolver obtains TTLs from DNS resource records using the system's
// configured recursive resolver. It is entirely in-process and requires no
// DNS daemon owned by the plugin.
type WireResolver struct {
	Servers      []string
	Timeout      time.Duration
	exchangeHook func(context.Context, string, []byte) ([]byte, error)
}

func NewWireResolver() Resolver {
	servers := resolvConfServers()
	if len(servers) == 0 {
		// Non-Unix development hosts do not expose resolv.conf. Local fixtures
		// still get deterministic bounded caching through the adapter.
		return NetResolverAdapter{TTL: time.Minute, NegativeTTL: 15 * time.Second}
	}
	return &WireResolver{Servers: servers, Timeout: 5 * time.Second}
}

func resolvConfServers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "nameserver" && net.ParseIP(fields[1]) != nil {
			servers = append(servers, net.JoinHostPort(fields[1], "53"))
		}
	}
	return servers
}

func (resolver *WireResolver) Lookup(ctx context.Context, host string) (DNSResult, error) {
	var combined []net.IPAddr
	minimumTTL := time.Duration(0)
	minimumTTLSet := false
	negativeTTL := time.Duration(0)
	negativeTTLSet := false
	var lastErr error
	var transientErr error
	for _, queryType := range []uint16{1, 28} {
		addresses, ttl, negative, err := resolver.lookupType(ctx, host, queryType)
		if errors.Is(err, ErrDNSNotFound) || negative > 0 {
			negativeTTL, negativeTTLSet = lowerTTL(negativeTTL, negativeTTLSet, negative)
		}
		if err != nil {
			lastErr = err
			if !errors.Is(err, ErrDNSNotFound) {
				transientErr = err
			}
			continue
		}
		combined = append(combined, addresses...)
		minimumTTL, minimumTTLSet = lowerTTL(minimumTTL, minimumTTLSet, ttl)
	}
	if len(combined) == 0 {
		if transientErr != nil {
			lastErr = transientErr
		}
		if lastErr == nil {
			lastErr = ErrDNSNotFound
		}
		return DNSResult{NegativeTTL: negativeTTL}, lastErr
	}
	return DNSResult{Addresses: combined, TTL: minimumTTL, NegativeTTL: negativeTTL}, nil
}

func (resolver *WireResolver) lookupType(ctx context.Context, host string, queryType uint16) ([]net.IPAddr, time.Duration, time.Duration, error) {
	return resolver.lookupTypeChain(ctx, normalizeDNSName(host), queryType, make(map[string]bool), 0)
}

func (resolver *WireResolver) lookupTypeChain(ctx context.Context, host string, queryType uint16, path map[string]bool, depth int) ([]net.IPAddr, time.Duration, time.Duration, error) {
	if host == "" || depth > maxDNSCNAMEHops || path[host] {
		return nil, 0, 0, errDNSWire
	}
	path[host] = true
	defer delete(path, host)
	query, id, err := dnsQuery(host, queryType)
	if err != nil {
		return nil, 0, 0, err
	}
	var lastErr error
	for _, server := range resolver.Servers {
		response, err := resolver.exchangeQuery(ctx, server, query)
		if err != nil {
			lastErr = err
			continue
		}
		addresses, ttl, negative, canonical, hops, err := parseDNSResponse(response, id, queryType, host)
		if err == nil && len(addresses) == 0 && canonical != "" {
			if depth+hops > maxDNSCNAMEHops {
				lastErr = errDNSWire
				continue
			}
			var terminalTTL, terminalNegative time.Duration
			var terminalErr error
			addresses, terminalTTL, terminalNegative, terminalErr = resolver.lookupTypeChain(ctx, canonical, queryType, path, depth+hops)
			if terminalErr != nil {
				if errors.Is(terminalErr, ErrDNSNotFound) {
					negative, _ = lowerTTL(terminalNegative, true, ttl)
					return nil, 0, negative, terminalErr
				}
				lastErr = terminalErr
				continue
			}
			ttl, _ = lowerTTL(ttl, true, terminalTTL)
			err = nil
		}
		if err == nil || errors.Is(err, ErrDNSNotFound) {
			return addresses, ttl, negative, err
		}
		lastErr = err
	}
	return nil, 0, 0, lastErr
}

func (resolver *WireResolver) exchangeQuery(ctx context.Context, server string, query []byte) ([]byte, error) {
	if resolver.exchangeHook != nil {
		return resolver.exchangeHook(ctx, server, query)
	}
	return resolver.exchange(ctx, server, query)
}

func (resolver *WireResolver) exchange(ctx context.Context, server string, query []byte) ([]byte, error) {
	timeout := resolver.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	connection, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	deadline := time.Now().Add(timeout)
	if ctxDeadline, found := ctx.Deadline(); found && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = connection.SetDeadline(deadline)
	if _, err := connection.Write(query); err != nil {
		return nil, err
	}
	buffer := make([]byte, 4096)
	count, err := connection.Read(buffer)
	if err != nil {
		return nil, err
	}
	if count < 12 {
		return nil, errDNSWire
	}
	if binary.BigEndian.Uint16(buffer[2:4])&0x0200 != 0 {
		return resolver.exchangeTCP(ctx, server, query, deadline)
	}
	return append([]byte(nil), buffer[:count]...), nil
}

func (resolver *WireResolver) exchangeTCP(ctx context.Context, server string, query []byte, deadline time.Time) ([]byte, error) {
	timeout := time.Until(deadline)
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	connection, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(deadline)
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if err := writeAll(connection, framed); err != nil {
		return nil, err
	}
	var length [2]byte
	if _, err := io.ReadFull(connection, length[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(length[:]))
	if size < 12 {
		return nil, errDNSWire
	}
	response := make([]byte, size)
	if _, err := io.ReadFull(connection, response); err != nil {
		return nil, err
	}
	return response, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[count:]
	}
	return nil
}

func dnsQuery(host string, queryType uint16) ([]byte, uint16, error) {
	var random [2]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(random[:])
	message := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(message[0:2], id)
	binary.BigEndian.PutUint16(message[2:4], 0x0100)
	binary.BigEndian.PutUint16(message[4:6], 1)
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, errDNSWire
		}
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0, byte(queryType>>8), byte(queryType), 0, 1)
	return message, id, nil
}

type dnsCNAMERecord struct {
	target string
	ttl    time.Duration
}

type dnsAddressRecord struct {
	address net.IPAddr
	ttl     time.Duration
}

func parseDNSResponse(message []byte, id uint16, queryType uint16, expectedName string) ([]net.IPAddr, time.Duration, time.Duration, string, int, error) {
	if len(message) < 12 || binary.BigEndian.Uint16(message[:2]) != id || binary.BigEndian.Uint16(message[2:4])&0x8000 == 0 {
		return nil, 0, 0, "", 0, errDNSWire
	}
	rcode := binary.BigEndian.Uint16(message[2:4]) & 0x000f
	questions := int(binary.BigEndian.Uint16(message[4:6]))
	answers := int(binary.BigEndian.Uint16(message[6:8]))
	authorities := int(binary.BigEndian.Uint16(message[8:10]))
	if questions != 1 {
		return nil, 0, 0, "", 0, errDNSWire
	}
	offset := 12
	questionName := ""
	for range questions {
		var err error
		questionName, offset, err = readDNSName(message, offset)
		if err != nil || offset+4 > len(message) {
			return nil, 0, 0, "", 0, errDNSWire
		}
		if binary.BigEndian.Uint16(message[offset:offset+2]) != queryType || binary.BigEndian.Uint16(message[offset+2:offset+4]) != 1 {
			return nil, 0, 0, "", 0, errDNSWire
		}
		offset += 4
	}
	if questionName != normalizeDNSName(expectedName) {
		return nil, 0, 0, "", 0, errDNSWire
	}
	cnames := make(map[string]dnsCNAMERecord)
	addressRecords := make(map[string][]dnsAddressRecord)
	negativeTTL := time.Duration(0)
	negativeTTLSet := false
	authoritativeNODATA := false
	for index := 0; index < answers+authorities; index++ {
		owner, next, err := readDNSName(message, offset)
		if err != nil || next+10 > len(message) {
			return nil, 0, 0, "", 0, errDNSWire
		}
		recordType := binary.BigEndian.Uint16(message[next : next+2])
		recordClass := binary.BigEndian.Uint16(message[next+2 : next+4])
		ttlSeconds := binary.BigEndian.Uint32(message[next+4 : next+8])
		length := int(binary.BigEndian.Uint16(message[next+8 : next+10]))
		dataOffset := next + 10
		if dataOffset+length > len(message) {
			return nil, 0, 0, "", 0, errDNSWire
		}
		if index < answers && recordClass == 1 && recordType == 5 {
			target, cnameEnd, cnameErr := readDNSName(message, dataOffset)
			if cnameErr != nil || cnameEnd != dataOffset+length || target == "" || target == owner {
				return nil, 0, 0, "", 0, errDNSWire
			}
			ttl := time.Duration(ttlSeconds) * time.Second
			if previous, found := cnames[owner]; found {
				if previous.target != target {
					return nil, 0, 0, "", 0, errDNSWire
				}
				ttl, _ = lowerTTL(previous.ttl, true, ttl)
			}
			cnames[owner] = dnsCNAMERecord{target: target, ttl: ttl}
		}
		if index < answers && recordClass == 1 && recordType == queryType && ((recordType == 1 && length == 4) || (recordType == 28 && length == 16)) {
			addressRecords[owner] = append(addressRecords[owner], dnsAddressRecord{
				address: net.IPAddr{IP: append(net.IP(nil), message[dataOffset:dataOffset+length]...)},
				ttl:     time.Duration(ttlSeconds) * time.Second,
			})
		}
		if index >= answers && recordClass == 1 && recordType == 6 && length >= 20 {
			authoritativeNODATA = true
			minimum := binary.BigEndian.Uint32(message[dataOffset+length-4 : dataOffset+length])
			negative := time.Duration(min(ttlSeconds, minimum)) * time.Second
			negativeTTL, negativeTTLSet = lowerTTL(negativeTTL, negativeTTLSet, negative)
		}
		offset = dataOffset + length
	}
	current := questionName
	visited := map[string]bool{current: true}
	minimumTTL := time.Duration(0)
	minimumTTLSet := false
	hops := 0
	for {
		cname, found := cnames[current]
		if !found {
			break
		}
		if len(addressRecords[current]) > 0 || hops >= maxDNSCNAMEHops || visited[cname.target] {
			return nil, 0, negativeTTL, "", 0, errDNSWire
		}
		minimumTTL, minimumTTLSet = lowerTTL(minimumTTL, minimumTTLSet, cname.ttl)
		current = cname.target
		visited[current] = true
		hops++
	}
	if rcode != 0 && rcode != 3 {
		return nil, 0, negativeTTL, "", 0, errDNSWire
	}
	if rcode == 3 {
		if len(addressRecords[current]) > 0 {
			return nil, 0, 0, "", 0, errDNSWire
		}
		return nil, 0, effectiveNegativeTTL(negativeTTL, negativeTTLSet, minimumTTL, minimumTTLSet), "", hops, ErrDNSNotFound
	}
	if records := addressRecords[current]; len(records) > 0 {
		addresses := make([]net.IPAddr, 0, len(records))
		for _, record := range records {
			addresses = append(addresses, record.address)
			minimumTTL, minimumTTLSet = lowerTTL(minimumTTL, minimumTTLSet, record.ttl)
		}
		return addresses, minimumTTL, negativeTTL, "", hops, nil
	}
	if authoritativeNODATA {
		return nil, 0, effectiveNegativeTTL(negativeTTL, negativeTTLSet, minimumTTL, minimumTTLSet), "", hops, ErrDNSNotFound
	}
	if hops > 0 {
		return nil, minimumTTL, negativeTTL, current, hops, nil
	}
	return nil, 0, negativeTTL, "", 0, errDNSWire
}

func effectiveNegativeTTL(negativeTTL time.Duration, negativeSet bool, cnameTTL time.Duration, cnameSet bool) time.Duration {
	if !negativeSet {
		return 0
	}
	if !cnameSet {
		return negativeTTL
	}
	result, _ := lowerTTL(negativeTTL, true, cnameTTL)
	return result
}

func lowerTTL(current time.Duration, initialized bool, candidate time.Duration) (time.Duration, bool) {
	if !initialized || candidate < current {
		return candidate, true
	}
	return current, true
}

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func readDNSName(message []byte, offset int) (string, int, error) {
	labels := make([]string, 0, 4)
	next := -1
	visited := make(map[int]bool)
	for steps := 0; steps < 128; steps++ {
		if offset >= len(message) || visited[offset] {
			return "", 0, errDNSWire
		}
		visited[offset] = true
		length := int(message[offset])
		if length == 0 {
			if next < 0 {
				next = offset + 1
			}
			name := normalizeDNSName(strings.Join(labels, "."))
			if len(name) > 253 {
				return "", 0, errDNSWire
			}
			return name, next, nil
		}
		if length&0xc0 == 0xc0 {
			if offset+2 > len(message) {
				return "", 0, errDNSWire
			}
			pointer := int(binary.BigEndian.Uint16(message[offset:offset+2]) & 0x3fff)
			if pointer >= offset || pointer >= len(message) {
				return "", 0, errDNSWire
			}
			if next < 0 {
				next = offset + 2
			}
			offset = pointer
			continue
		}
		if length&0xc0 != 0 || length > 63 || offset+1+length > len(message) {
			return "", 0, errDNSWire
		}
		label := string(message[offset+1 : offset+1+length])
		if label == "" {
			return "", 0, errDNSWire
		}
		labels = append(labels, strings.ToLower(label))
		offset += 1 + length
	}
	return "", 0, errDNSWire
}

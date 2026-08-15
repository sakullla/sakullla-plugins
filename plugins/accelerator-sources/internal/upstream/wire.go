package upstream

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"time"
)

var errDNSWire = errors.New("invalid DNS wire response")

// WireResolver obtains TTLs from DNS resource records using the system's
// configured recursive resolver. It is entirely in-process and requires no
// DNS daemon owned by the plugin.
type WireResolver struct {
	Servers []string
	Timeout time.Duration
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
	negativeTTL := 15 * time.Second
	var lastErr error
	for _, queryType := range []uint16{1, 28} {
		addresses, ttl, negative, err := resolver.lookupType(ctx, host, queryType)
		if negative > 0 && negative < negativeTTL {
			negativeTTL = negative
		}
		if err != nil {
			lastErr = err
			continue
		}
		combined = append(combined, addresses...)
		if minimumTTL == 0 || ttl < minimumTTL {
			minimumTTL = ttl
		}
	}
	if len(combined) == 0 {
		if lastErr == nil {
			lastErr = ErrDNSNotFound
		}
		return DNSResult{NegativeTTL: negativeTTL}, lastErr
	}
	return DNSResult{Addresses: combined, TTL: minimumTTL, NegativeTTL: negativeTTL}, nil
}

func (resolver *WireResolver) lookupType(ctx context.Context, host string, queryType uint16) ([]net.IPAddr, time.Duration, time.Duration, error) {
	query, id, err := dnsQuery(host, queryType)
	if err != nil {
		return nil, 0, 0, err
	}
	var lastErr error
	for _, server := range resolver.Servers {
		response, err := resolver.exchange(ctx, server, query)
		if err != nil {
			lastErr = err
			continue
		}
		addresses, ttl, negative, err := parseDNSResponse(response, id, queryType)
		if err == nil || errors.Is(err, ErrDNSNotFound) {
			return addresses, ttl, negative, err
		}
		lastErr = err
	}
	return nil, 0, 0, lastErr
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
	if count < 12 || binary.BigEndian.Uint16(buffer[2:4])&0x0200 != 0 {
		return nil, errDNSWire
	}
	return append([]byte(nil), buffer[:count]...), nil
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

func parseDNSResponse(message []byte, id uint16, queryType uint16) ([]net.IPAddr, time.Duration, time.Duration, error) {
	if len(message) < 12 || binary.BigEndian.Uint16(message[:2]) != id || binary.BigEndian.Uint16(message[2:4])&0x8000 == 0 {
		return nil, 0, 0, errDNSWire
	}
	rcode := binary.BigEndian.Uint16(message[2:4]) & 0x000f
	questions := int(binary.BigEndian.Uint16(message[4:6]))
	answers := int(binary.BigEndian.Uint16(message[6:8]))
	authorities := int(binary.BigEndian.Uint16(message[8:10]))
	offset := 12
	for range questions {
		var err error
		offset, err = skipDNSName(message, offset)
		if err != nil || offset+4 > len(message) {
			return nil, 0, 0, errDNSWire
		}
		offset += 4
	}
	var addresses []net.IPAddr
	minimumTTL := time.Duration(0)
	negativeTTL := 15 * time.Second
	for index := 0; index < answers+authorities; index++ {
		next, err := skipDNSName(message, offset)
		if err != nil || next+10 > len(message) {
			return nil, 0, 0, errDNSWire
		}
		recordType := binary.BigEndian.Uint16(message[next : next+2])
		ttlSeconds := binary.BigEndian.Uint32(message[next+4 : next+8])
		length := int(binary.BigEndian.Uint16(message[next+8 : next+10]))
		dataOffset := next + 10
		if dataOffset+length > len(message) {
			return nil, 0, 0, errDNSWire
		}
		if index < answers && recordType == queryType && ((recordType == 1 && length == 4) || (recordType == 28 && length == 16)) {
			addresses = append(addresses, net.IPAddr{IP: append(net.IP(nil), message[dataOffset:dataOffset+length]...)})
			ttl := time.Duration(ttlSeconds) * time.Second
			if minimumTTL == 0 || ttl < minimumTTL {
				minimumTTL = ttl
			}
		}
		if index >= answers && recordType == 6 && length >= 20 {
			minimum := binary.BigEndian.Uint32(message[dataOffset+length-4 : dataOffset+length])
			negative := time.Duration(min(ttlSeconds, minimum)) * time.Second
			if negative > 0 && negative < negativeTTL {
				negativeTTL = negative
			}
		}
		offset = dataOffset + length
	}
	if rcode == 3 || len(addresses) == 0 {
		return nil, 0, negativeTTL, ErrDNSNotFound
	}
	if rcode != 0 {
		return nil, 0, negativeTTL, errDNSWire
	}
	return addresses, minimumTTL, negativeTTL, nil
}

func skipDNSName(message []byte, offset int) (int, error) {
	for steps := 0; steps < 128; steps++ {
		if offset >= len(message) {
			return 0, errDNSWire
		}
		length := int(message[offset])
		if length == 0 {
			return offset + 1, nil
		}
		if length&0xc0 == 0xc0 {
			if offset+2 > len(message) {
				return 0, errDNSWire
			}
			return offset + 2, nil
		}
		if length > 63 || offset+1+length > len(message) {
			return 0, errDNSWire
		}
		offset += 1 + length
	}
	return 0, errDNSWire
}

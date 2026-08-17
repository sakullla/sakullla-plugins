package shadowsocksserver

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

const (
	ShareHostSourceDDNS = "ddns"
	ShareHostSourceIPv4 = "ipv4"
	ShareHostSourceIPv6 = "ipv6"
	MissingShareHost    = "missing public share address"
)

var ErrMissingShareHost = errors.New(MissingShareHost)

// NodeAddresses is the Host projection of this agent's public identity.
// The plugin never probes a public IP or writes DDNS.
type NodeAddresses struct {
	DDNS string `json:"ddns_domain,omitempty"`
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

// ListenBinding is the dedicated TCP+UDP socket Host bound for this instance.
// BindHost may be a wildcard; share host is selected from NodeAddresses.
type ListenBinding struct {
	Port     int    `json:"port"`
	BindHost string `json:"bind_host,omitempty"`
	TCP      bool   `json:"tcp"`
	UDP      bool   `json:"udp"`
}

// ShareEndpoint is the copyable listen projection for SIP002 and existing L4.
type ShareEndpoint struct {
	Host      string `json:"host,omitempty"`
	Port      int    `json:"port,omitempty"`
	HostPort  string `json:"host_port,omitempty"`
	Source    string `json:"source,omitempty"`
	TCP       bool   `json:"tcp"`
	UDP       bool   `json:"udp"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// L4Backend matches reverse-l4 backend_host / backend_port.
type L4Backend struct {
	BackendHost string `json:"backend_host"`
	BackendPort uint16 `json:"backend_port"`
}

// DualStackListen is one TCP+UDP port on the deploy node.
func DualStackListen(port int, bindHost string) (ListenBinding, error) {
	binding := ListenBinding{Port: port, BindHost: strings.TrimSpace(bindHost), TCP: true, UDP: true}
	if err := binding.Validate(); err != nil {
		return ListenBinding{}, err
	}
	return binding, nil
}

func (b ListenBinding) Validate() error {
	if b.Port < 1 || b.Port > 65535 || !b.TCP || !b.UDP {
		return ErrInvalid
	}
	return nil
}

func (b ListenBinding) Share(addresses NodeAddresses) ShareEndpoint {
	return ProjectShareEndpoint(b, addresses)
}

// SelectHost prefers DDNS, then IPv4, then IPv6. Wildcard and loopback are skipped.
func (a NodeAddresses) SelectHost() (host, source string, ok bool) {
	if host, ok = shareableHost(a.DDNS); ok {
		return host, ShareHostSourceDDNS, true
	}
	if host, ok = shareableHost(a.IPv4); ok {
		return host, ShareHostSourceIPv4, true
	}
	if host, ok = shareableHost(a.IPv6); ok {
		return host, ShareHostSourceIPv6, true
	}
	return "", "", false
}

// ProjectShareEndpoint maps the live bind and Host node addresses to a shareable endpoint.
func ProjectShareEndpoint(binding ListenBinding, addresses NodeAddresses) ShareEndpoint {
	if err := binding.Validate(); err != nil {
		return ShareEndpoint{Reason: MissingShareHost}
	}
	endpoint := ShareEndpoint{Port: binding.Port, TCP: true, UDP: true}
	host, source, ok := addresses.SelectHost()
	if !ok {
		endpoint.Reason = MissingShareHost
		return endpoint
	}
	endpoint.Host = host
	endpoint.HostPort = net.JoinHostPort(host, strconv.Itoa(binding.Port))
	endpoint.Source = source
	endpoint.Available = true
	return endpoint
}

func (e ShareEndpoint) CopyableHostPort() (string, error) {
	if !e.Available || e.HostPort == "" {
		return "", ErrMissingShareHost
	}
	return e.HostPort, nil
}

func (e ShareEndpoint) L4Backend() (L4Backend, error) {
	if !e.Available || e.Host == "" || e.Port < 1 || e.Port > 65535 || !validL4BackendHost(e.Host) {
		return L4Backend{}, ErrMissingShareHost
	}
	return L4Backend{BackendHost: e.Host, BackendPort: uint16(e.Port)}, nil
}

func shareableHost(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") && len(value) > 2 {
		value = value[1 : len(value)-1]
	}
	if value == "" {
		return "", false
	}
	if ip := net.ParseIP(value); ip != nil {
		if ip.IsUnspecified() || ip.IsLoopback() {
			return "", false
		}
		return ip.String(), true
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" || strings.EqualFold(value, "localhost") || strings.HasSuffix(strings.ToLower(value), ".localhost") {
		return "", false
	}
	if strings.Contains(value, "://") || strings.ContainsAny(value, " /\\?#@:[]%\x00\r\n\t") || len(value) > 253 {
		return "", false
	}
	return value, true
}

func validL4BackendHost(value string) bool {
	return value != "" && len(value) <= 253 && !strings.Contains(value, "://") && !strings.ContainsAny(value, "/\\ \t\r\n\x00")
}

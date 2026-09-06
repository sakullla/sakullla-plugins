package shadowsocksserver

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	pluginsdk "github.com/sakullla/nginx-reverse-emby/plugin-sdk/go"
)

const scopedSecretPurpose = "shadowsocks-inbound"

type managedHostClient interface {
	hostRuntimeCaller
	ManagedNetwork(context.Context, pluginsdk.ManagedNetworkRequest) (pluginsdk.ManagedNetworkResponse, error)
	ScopedSecret(context.Context, pluginsdk.ScopedSecretRequest) (pluginsdk.ScopedSecretResponse, error)
}

func managedRequestID(prefix string) string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return prefix + "-fallback"
	}
	return prefix + "-" + hex.EncodeToString(value[:])
}

func (runtime *hostCapabilityRuntime) bind(instanceID, generation string) error {
	binding := pluginsdk.ManagedBinding{InstanceID: instanceID, Generation: generation, EntryID: instanceID}
	if binding.Validate() != nil {
		return ErrTypedHandlesUnavailable
	}
	runtime.mu.Lock()
	runtime.binding = binding
	runtime.mu.Unlock()
	return nil
}

func (runtime *hostCapabilityRuntime) managedBinding() (pluginsdk.ManagedBinding, error) {
	if runtime == nil || runtime.managed == nil {
		return pluginsdk.ManagedBinding{}, ErrTypedHandlesUnavailable
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.binding.Validate() != nil {
		return pluginsdk.ManagedBinding{}, ErrTypedHandlesUnavailable
	}
	return runtime.binding, nil
}

func (runtime *hostCapabilityRuntime) scopedReference(id, version string) (pluginsdk.ScopedSecretReference, error) {
	binding, err := runtime.managedBinding()
	if err != nil {
		return pluginsdk.ScopedSecretReference{}, err
	}
	return pluginsdk.ScopedSecretReference{InstanceID: binding.InstanceID, ID: id, Version: version, Scope: scopedSecretPurpose}, nil
}

func (runtime *hostCapabilityRuntime) importSecret(ctx context.Context, id string, value []byte) (pluginsdk.ScopedSecretReference, error) {
	binding, err := runtime.managedBinding()
	if err != nil {
		return pluginsdk.ScopedSecretReference{}, err
	}
	material, err := pluginsdk.NewManagedSecretMaterial(value)
	if err != nil {
		return pluginsdk.ScopedSecretReference{}, ErrTypedHandlesUnavailable
	}
	defer material.Close()
	response, err := runtime.managed.ScopedSecret(ctx, pluginsdk.ScopedSecretRequest{Action: pluginsdk.ScopedSecretCreate, Binding: binding, Reference: pluginsdk.ScopedSecretReference{InstanceID: binding.InstanceID, ID: id, Scope: scopedSecretPurpose}, Material: material})
	if err != nil {
		return pluginsdk.ScopedSecretReference{}, ErrTypedHandlesUnavailable
	}
	return response.Reference, nil
}

func opaqueSecretID(kind string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", ErrDenied
	}
	return "ss-" + kind + "-" + hex.EncodeToString(value[:]), nil
}

func (runtime *hostCapabilityRuntime) importOpaqueSecret(ctx context.Context, kind string, value []byte) (pluginsdk.ScopedSecretReference, error) {
	id, err := opaqueSecretID(kind)
	if err != nil {
		return pluginsdk.ScopedSecretReference{}, err
	}
	return runtime.importSecret(ctx, id, value)
}

func (runtime *hostCapabilityRuntime) createReplacementSecret(ctx context.Context, kind, method string) (pluginsdk.ScopedSecretReference, error) {
	var value []byte
	if SS2022Method(method) {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return pluginsdk.ScopedSecretReference{}, ErrDenied
		}
		input := base64.RawURLEncoding.EncodeToString(raw)
		clear(raw)
		mapped, err := MapSS2022PSK(method, input)
		if err != nil {
			return pluginsdk.ScopedSecretReference{}, err
		}
		value = []byte(mapped)
	} else if SupportedMethod(method) {
		password, err := GenerateLegacyPassword()
		if err != nil {
			return pluginsdk.ScopedSecretReference{}, err
		}
		value = []byte(password)
	} else {
		return pluginsdk.ScopedSecretReference{}, ErrInvalid
	}
	defer clear(value)
	return runtime.importOpaqueSecret(ctx, kind, value)
}

func (runtime *hostCapabilityRuntime) revokeReferences(ctx context.Context, references []pluginsdk.ScopedSecretReference) {
	for _, reference := range references {
		_ = runtime.revokeSecret(ctx, reference.ID, reference.Version)
	}
}

func (runtime *hostCapabilityRuntime) Resolve(ctx context.Context, ref, version string) ([]byte, error) {
	binding, err := runtime.managedBinding()
	if err != nil {
		return nil, err
	}
	reference, err := runtime.scopedReference(ref, version)
	if err != nil {
		return nil, err
	}
	response, err := runtime.managed.ScopedSecret(ctx, pluginsdk.ScopedSecretRequest{Action: pluginsdk.ScopedSecretRead, Binding: binding, Reference: reference})
	if err != nil || response.Material == nil {
		return nil, ErrDenied
	}
	defer response.Material.Close()
	var result []byte
	if err := response.Material.WithBytes(func(value []byte) error {
		result = append([]byte(nil), value...)
		return nil
	}); err != nil {
		return nil, ErrDenied
	}
	return result, nil
}

func (runtime *hostCapabilityRuntime) Verify(ctx context.Context, ref, version string, material []byte) error {
	stored, err := runtime.Resolve(ctx, ref, version)
	if err != nil {
		return err
	}
	defer clear(stored)
	if len(stored) != len(material) || subtle.ConstantTimeCompare(stored, material) != 1 {
		return ErrDenied
	}
	return nil
}

func (runtime *hostCapabilityRuntime) Rotate(ctx context.Context, id, ref, version, _ string) (*SecretOnce, error) {
	binding, err := runtime.managedBinding()
	if err != nil {
		return nil, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, ErrDenied
	}
	value := []byte(base64.RawURLEncoding.EncodeToString(raw))
	clear(raw)
	defer clear(value)
	material, err := pluginsdk.NewManagedSecretMaterial(value)
	if err != nil {
		return nil, ErrDenied
	}
	defer material.Close()
	action := pluginsdk.ScopedSecretRotate
	reference, err := runtime.scopedReference(ref, version)
	if version == InitialSecretVersion() {
		action = pluginsdk.ScopedSecretCreate
		reference.Version = ""
	}
	if err != nil {
		return nil, err
	}
	response, err := runtime.managed.ScopedSecret(ctx, pluginsdk.ScopedSecretRequest{Action: action, Binding: binding, Reference: reference, Material: material})
	if err != nil {
		return nil, ErrDenied
	}
	return NewSecretOnce(response.Reference.ID, response.Reference.Version, value), nil
}

func (runtime *hostCapabilityRuntime) revokeSecret(ctx context.Context, ref, version string) error {
	binding, err := runtime.managedBinding()
	if err != nil {
		return err
	}
	reference, err := runtime.scopedReference(ref, version)
	if err != nil {
		return err
	}
	_, err = runtime.managed.ScopedSecret(ctx, pluginsdk.ScopedSecretRequest{Action: pluginsdk.ScopedSecretRevoke, Binding: binding, Reference: reference})
	if err != nil {
		return ErrDenied
	}
	return nil
}

func (runtime *hostCapabilityRuntime) migrateLegacySecrets(ctx context.Context, configuration Configuration, secrets map[string]string) (Configuration, []pluginsdk.ScopedSecretReference, error) {
	next := clone(configuration)
	migrated := map[string]pluginsdk.ScopedSecretReference{}
	created := make([]pluginsdk.ScopedSecretReference, 0, len(secrets))
	fail := func(err error) (Configuration, []pluginsdk.ScopedSecretReference, error) {
		runtime.revokeReferences(ctx, created)
		return Configuration{}, nil, err
	}
	migrate := func(ref, version string) (string, error) {
		key := issuedSecretKey(ref, version)
		if reference, ok := migrated[key]; ok {
			return reference.Version, nil
		}
		material, ok := secrets[key]
		if !ok || material == "" {
			return "", ErrDenied
		}
		value := []byte(material)
		reference, err := runtime.importOpaqueSecret(ctx, "migrated", value)
		clear(value)
		if err != nil {
			return "", ErrTypedHandlesUnavailable
		}
		migrated[key] = reference
		created = append(created, reference)
		return reference.Version, nil
	}
	for listenerIndex := range next.Listeners {
		listener := &next.Listeners[listenerIndex]
		if listener.ServerSecretRef != "" {
			version, err := migrate(listener.ServerSecretRef, listener.ServerSecretVersion)
			if err != nil {
				return fail(err)
			}
			listener.ServerSecretRef = migrated[issuedSecretKey(listener.ServerSecretRef, listener.ServerSecretVersion)].ID
			listener.ServerSecretVersion = version
		}
		for userIndex := range listener.Users {
			user := &listener.Users[userIndex]
			version, err := migrate(user.SecretRef, user.SecretVersion)
			if err != nil {
				return fail(err)
			}
			user.SecretRef = migrated[issuedSecretKey(user.SecretRef, user.SecretVersion)].ID
			user.SecretVersion = version
		}
	}
	if err := next.Validate(); err != nil {
		return fail(err)
	}
	return next, created, nil
}

type managedNetworkDialer struct{ runtime *hostCapabilityRuntime }

func (dialer managedNetworkDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrInvalid
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, ErrInvalid
	}
	binding, err := dialer.runtime.managedBinding()
	if err != nil {
		return nil, err
	}
	endpoint := pluginsdk.ManagedNetworkEndpoint{Host: strings.Trim(host, "[]"), Port: port}
	request := pluginsdk.ManagedNetworkRequest{Action: pluginsdk.ManagedNetworkDial, Binding: binding, RequestID: managedRequestID("dial"), Endpoint: &endpoint, Protocol: network, WaitMS: 5000}
	if network == "udp" {
		request.IdleMS = 30000
	}
	response, err := dialer.runtime.managed.ManagedNetwork(ctx, request)
	if err != nil || response.Handle == nil {
		return nil, ErrDenied
	}
	return newManagedConn(dialer.runtime, *response.Handle, nil), nil
}

type managedConn struct {
	runtime *hostCapabilityRuntime
	handle  pluginsdk.ManagedNetworkHandle
	remote  net.Addr
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	readBy  time.Time
	writeBy time.Time
	closed  bool
}

func newManagedConn(runtime *hostCapabilityRuntime, handle pluginsdk.ManagedNetworkHandle, source *pluginsdk.ManagedSourceMetadata) *managedConn {
	var remote net.Addr = managedAddr{network: handle.Protocol, value: handle.Token}
	if source != nil {
		remote = endpointAddr(handle.Protocol, source.Source)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	return &managedConn{runtime: runtime, handle: handle, remote: remote, ctx: lifetime, cancel: cancel}
}

func endpointAddr(network string, endpoint pluginsdk.ManagedNetworkEndpoint) net.Addr {
	address := net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))
	if network == "udp" {
		value, _ := net.ResolveUDPAddr("udp", address)
		return value
	}
	value, _ := net.ResolveTCPAddr("tcp", address)
	return value
}

func (conn *managedConn) context(deadline time.Time) (context.Context, context.CancelFunc) {
	if deadline.IsZero() {
		return context.WithCancel(conn.ctx)
	}
	return context.WithDeadline(conn.ctx, deadline)
}

func (conn *managedConn) Read(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	conn.mu.Lock()
	deadline, closed := conn.readBy, conn.closed
	conn.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	ctx, cancel := conn.context(deadline)
	defer cancel()
	action, maximum := pluginsdk.ManagedNetworkRead, min(len(value), pluginsdk.ManagedNetworkMaxChunkBytes)
	if conn.handle.Protocol == "udp" {
		action, maximum = pluginsdk.ManagedNetworkReceive, pluginsdk.ManagedNetworkMaxDatagramBytes
	}
	for {
		request := pluginsdk.ManagedNetworkRequest{Action: action, Binding: conn.handle.Binding, RequestID: managedRequestID("read"), Handle: &conn.handle, MaxBytes: maximum, WaitMS: 30000}
		response, err := conn.runtime.managed.ManagedNetwork(ctx, request)
		if err != nil {
			return 0, err
		}
		if response.Idle {
			continue
		}
		n := copy(value, response.Data)
		if response.EOF {
			return n, io.EOF
		}
		return n, nil
	}
}

func (conn *managedConn) Write(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	conn.mu.Lock()
	deadline, closed := conn.writeBy, conn.closed
	conn.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	ctx, cancel := conn.context(deadline)
	defer cancel()
	action := pluginsdk.ManagedNetworkWrite
	if conn.handle.Protocol == "udp" {
		action = pluginsdk.ManagedNetworkSend
	}
	total := 0
	for total < len(value) {
		chunk := value[total:]
		if action == pluginsdk.ManagedNetworkWrite && len(chunk) > pluginsdk.ManagedNetworkMaxChunkBytes {
			chunk = chunk[:pluginsdk.ManagedNetworkMaxChunkBytes]
		}
		request := pluginsdk.ManagedNetworkRequest{Action: action, Binding: conn.handle.Binding, RequestID: managedRequestID("write"), Handle: &conn.handle, Data: chunk, WaitMS: 30000}
		response, err := conn.runtime.managed.ManagedNetwork(ctx, request)
		if err != nil {
			return total, err
		}
		total += response.Written
		if action == pluginsdk.ManagedNetworkSend {
			break
		}
	}
	return total, nil
}

func (conn *managedConn) Close() error {
	conn.mu.Lock()
	if conn.closed {
		conn.mu.Unlock()
		return nil
	}
	conn.closed = true
	conn.cancel()
	conn.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := conn.runtime.managed.ManagedNetwork(ctx, pluginsdk.ManagedNetworkRequest{Action: pluginsdk.ManagedNetworkClose, Binding: conn.handle.Binding, RequestID: managedRequestID("close"), Handle: &conn.handle})
	return err
}
func (conn *managedConn) LocalAddr() net.Addr {
	return managedAddr{network: conn.handle.Protocol, value: "host"}
}
func (conn *managedConn) RemoteAddr() net.Addr { return conn.remote }
func (conn *managedConn) SetDeadline(value time.Time) error {
	conn.mu.Lock()
	conn.readBy, conn.writeBy = value, value
	conn.mu.Unlock()
	return nil
}
func (conn *managedConn) SetReadDeadline(value time.Time) error {
	conn.mu.Lock()
	conn.readBy = value
	conn.mu.Unlock()
	return nil
}
func (conn *managedConn) SetWriteDeadline(value time.Time) error {
	conn.mu.Lock()
	conn.writeBy = value
	conn.mu.Unlock()
	return nil
}

type managedAddr struct{ network, value string }

func (address managedAddr) Network() string { return address.network }
func (address managedAddr) String() string  { return address.value }

type managedTCPListener struct {
	runtime *hostCapabilityRuntime
	handle  pluginsdk.ManagedNetworkHandle
	ctx     context.Context
	cancel  context.CancelFunc
	once    sync.Once
}

func (runtime *hostCapabilityRuntime) listenTCP(ctx context.Context, port int) (net.Listener, error) {
	binding, err := runtime.managedBinding()
	if err != nil {
		return nil, err
	}
	endpoint := pluginsdk.ManagedNetworkEndpoint{Host: "0.0.0.0", Port: port}
	response, err := runtime.managed.ManagedNetwork(ctx, pluginsdk.ManagedNetworkRequest{Action: pluginsdk.ManagedNetworkListen, Binding: binding, RequestID: managedRequestID("listen-tcp"), Endpoint: &endpoint, Protocol: "tcp", MaxFlows: 256, IdleMS: 300000})
	if err != nil || response.Handle == nil {
		return nil, ErrListenBind
	}
	lifetime, cancel := context.WithCancel(context.Background())
	return &managedTCPListener{runtime: runtime, handle: *response.Handle, ctx: lifetime, cancel: cancel}, nil
}

func (listener *managedTCPListener) Accept() (net.Conn, error) {
	for {
		response, err := listener.runtime.managed.ManagedNetwork(listener.ctx, pluginsdk.ManagedNetworkRequest{Action: pluginsdk.ManagedNetworkAccept, Binding: listener.handle.Binding, RequestID: managedRequestID("accept-tcp"), Handle: &listener.handle, WaitMS: 30000})
		if isManagedDeadline(err) && listener.ctx.Err() == nil {
			continue
		}
		if err != nil || response.Handle == nil || response.Source == nil {
			if err == nil {
				err = ErrTypedHandlesUnavailable
			}
			return nil, err
		}
		return newManagedConn(listener.runtime, *response.Handle, response.Source), nil
	}
}
func (listener *managedTCPListener) Close() error {
	var err error
	listener.once.Do(func() {
		listener.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err = listener.runtime.managed.ManagedNetwork(ctx, pluginsdk.ManagedNetworkRequest{Action: pluginsdk.ManagedNetworkClose, Binding: listener.handle.Binding, RequestID: managedRequestID("close-listener"), Handle: &listener.handle})
	})
	return err
}
func (listener *managedTCPListener) Addr() net.Addr {
	return managedAddr{network: "tcp", value: listener.handle.Token}
}

type managedPacket struct {
	data []byte
	addr managedAddr
}
type managedPacketConn struct {
	runtime         *hostCapabilityRuntime
	listener        pluginsdk.ManagedNetworkHandle
	ctx             context.Context
	cancel          context.CancelFunc
	packets         chan managedPacket
	mu              sync.Mutex
	flows           map[string]*managedConn
	readBy, writeBy time.Time
	once            sync.Once
}

func (runtime *hostCapabilityRuntime) listenUDP(ctx context.Context, port int) (net.PacketConn, error) {
	binding, err := runtime.managedBinding()
	if err != nil {
		return nil, err
	}
	endpoint := pluginsdk.ManagedNetworkEndpoint{Host: "0.0.0.0", Port: port}
	response, err := runtime.managed.ManagedNetwork(ctx, pluginsdk.ManagedNetworkRequest{Action: pluginsdk.ManagedNetworkListen, Binding: binding, RequestID: managedRequestID("listen-udp"), Endpoint: &endpoint, Protocol: "udp", MaxFlows: 256, IdleMS: 300000})
	if err != nil || response.Handle == nil {
		return nil, ErrListenBind
	}
	lifetime, cancel := context.WithCancel(context.Background())
	conn := &managedPacketConn{runtime: runtime, listener: *response.Handle, ctx: lifetime, cancel: cancel, packets: make(chan managedPacket, 256), flows: map[string]*managedConn{}}
	go conn.accept()
	return conn, nil
}

func (conn *managedPacketConn) accept() {
	for conn.ctx.Err() == nil {
		response, err := conn.runtime.managed.ManagedNetwork(conn.ctx, pluginsdk.ManagedNetworkRequest{Action: pluginsdk.ManagedNetworkAccept, Binding: conn.listener.Binding, RequestID: managedRequestID("accept-udp"), Handle: &conn.listener, WaitMS: 30000})
		if isManagedDeadline(err) && conn.ctx.Err() == nil {
			continue
		}
		if err != nil || response.Handle == nil || response.Source == nil {
			return
		}
		flow := newManagedConn(conn.runtime, *response.Handle, response.Source)
		addr := managedAddr{network: "udp", value: response.Handle.Token}
		conn.mu.Lock()
		conn.flows[addr.value] = flow
		conn.mu.Unlock()
		go conn.receive(flow, addr)
	}
}

func isManagedDeadline(err error) bool {
	var runtimeError *pluginsdk.RuntimeError
	return errors.As(err, &runtimeError) && runtimeError.Code == pluginsdk.ErrorDeadlineExceeded
}

func (conn *managedPacketConn) receive(flow *managedConn, addr managedAddr) {
	defer func() { conn.mu.Lock(); delete(conn.flows, addr.value); conn.mu.Unlock(); _ = flow.Close() }()
	buffer := make([]byte, pluginsdk.ManagedNetworkMaxDatagramBytes)
	for conn.ctx.Err() == nil {
		n, err := flow.Read(buffer)
		if err != nil {
			return
		}
		packet := managedPacket{data: append([]byte(nil), buffer[:n]...), addr: addr}
		select {
		case conn.packets <- packet:
		case <-conn.ctx.Done():
			return
		}
	}
}

func (conn *managedPacketConn) ReadFrom(value []byte) (int, net.Addr, error) {
	conn.mu.Lock()
	deadline := conn.readBy
	conn.mu.Unlock()
	var timer <-chan time.Time
	if !deadline.IsZero() {
		duration := time.Until(deadline)
		if duration <= 0 {
			return 0, nil, errors.New("i/o timeout")
		}
		timer = time.After(duration)
	}
	select {
	case packet := <-conn.packets:
		return copy(value, packet.data), packet.addr, nil
	case <-timer:
		return 0, nil, errors.New("i/o timeout")
	case <-conn.ctx.Done():
		return 0, nil, net.ErrClosed
	}
}
func (conn *managedPacketConn) WriteTo(value []byte, address net.Addr) (int, error) {
	addr, ok := address.(managedAddr)
	if !ok {
		return 0, ErrDenied
	}
	conn.mu.Lock()
	flow := conn.flows[addr.value]
	deadline := conn.writeBy
	conn.mu.Unlock()
	if flow == nil {
		return 0, ErrDenied
	}
	_ = flow.SetWriteDeadline(deadline)
	return flow.Write(value)
}
func (conn *managedPacketConn) Close() error {
	conn.once.Do(func() {
		conn.cancel()
		conn.mu.Lock()
		flows := make([]*managedConn, 0, len(conn.flows))
		for _, flow := range conn.flows {
			flows = append(flows, flow)
		}
		conn.flows = map[string]*managedConn{}
		conn.mu.Unlock()
		for _, flow := range flows {
			_ = flow.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.runtime.managed.ManagedNetwork(ctx, pluginsdk.ManagedNetworkRequest{Action: pluginsdk.ManagedNetworkClose, Binding: conn.listener.Binding, RequestID: managedRequestID("close-listener"), Handle: &conn.listener})
	})
	return nil
}
func (conn *managedPacketConn) LocalAddr() net.Addr {
	return managedAddr{network: "udp", value: conn.listener.Token}
}
func (conn *managedPacketConn) SetDeadline(value time.Time) error {
	conn.mu.Lock()
	conn.readBy, conn.writeBy = value, value
	conn.mu.Unlock()
	return nil
}
func (conn *managedPacketConn) SetReadDeadline(value time.Time) error {
	conn.mu.Lock()
	conn.readBy = value
	conn.mu.Unlock()
	return nil
}
func (conn *managedPacketConn) SetWriteDeadline(value time.Time) error {
	conn.mu.Lock()
	conn.writeBy = value
	conn.mu.Unlock()
	return nil
}

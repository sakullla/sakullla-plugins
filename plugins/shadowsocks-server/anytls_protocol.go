package shadowsocksserver

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ProtocolShadowsocks = "shadowsocks"
	ProtocolAnyTLS      = "anytls"

	anytlsCmdWaste               = 0
	anytlsCmdSYN                 = 1
	anytlsCmdPSH                 = 2
	anytlsCmdFIN                 = 3
	anytlsCmdSettings            = 4
	anytlsCmdAlert               = 5
	anytlsCmdUpdatePaddingScheme = 6
	anytlsCmdSYNACK              = 7
	anytlsCmdHeartRequest        = 8
	anytlsCmdHeartResponse       = 9
	anytlsCmdServerSettings      = 10

	anytlsHeaderSize = 7
	anytlsCheckMark  = -1
	uotMagicV2       = "sp.v2.udp-over-tcp.arpa"
	uotMagicLegacy   = "sp.udp-over-tcp.arpa"

	// defaultAnyTLSPaddingScheme is the confirmed Default Padding Scheme.
	// The text has no trailing newline, so padding-md5 stays stable for clients
	// that still use this scheme.
	defaultAnyTLSPaddingScheme = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000"
)

var ErrPaddingScheme = errors.New("AnyTLS 填充方案无效")

func (l ListenRule) AnyTLS() bool { return l.Protocol == ProtocolAnyTLS }

func (u Upstream) AnyTLS() bool { return u.Protocol == ProtocolAnyTLS }

func (u Upstream) tlsServerName() string {
	if strings.TrimSpace(u.SNI) != "" {
		return strings.TrimSpace(u.SNI)
	}
	return strings.Trim(strings.TrimSpace(u.Host), "[]")
}

func validatePaddingScheme(raw string) error {
	if raw == "" || len(raw) > 4096 || strings.ContainsAny(raw, "\r\x00") {
		return ErrPaddingScheme
	}
	seen := map[string]struct{}{}
	sawStop := false
	recordedStop := 0
	var indexes []int
	for _, line := range strings.Split(raw, "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || strings.TrimSpace(key) != key {
			return ErrPaddingScheme
		}
		if _, dup := seen[key]; dup {
			return ErrPaddingScheme
		}
		seen[key] = struct{}{}
		if key == "stop" {
			stop, err := strconv.Atoi(value)
			if err != nil || stop < 0 || stop > 64 {
				return ErrPaddingScheme
			}
			sawStop = true
			recordedStop = stop
			continue
		}
		index, err := strconv.Atoi(key)
		if err != nil || index < 0 || index > 63 || value == "" {
			return ErrPaddingScheme
		}
		if err := validatePaddingSpec(index, value); err != nil {
			return err
		}
		indexes = append(indexes, index)
	}
	if !sawStop {
		return ErrPaddingScheme
	}
	present := map[int]struct{}{}
	for _, index := range indexes {
		if index >= recordedStop {
			return ErrPaddingScheme
		}
		present[index] = struct{}{}
	}
	for index := 0; index < recordedStop; index++ {
		if _, ok := present[index]; !ok {
			return ErrPaddingScheme
		}
	}
	return nil
}

func validatePaddingSpec(index int, spec string) error {
	parts := strings.Split(spec, ",")
	if index == 0 && len(parts) != 1 {
		return ErrPaddingScheme
	}
	for _, part := range parts {
		if part == "c" {
			if index == 0 {
				return ErrPaddingScheme
			}
			continue
		}
		minText, maxText, ok := strings.Cut(part, "-")
		if !ok {
			return ErrPaddingScheme
		}
		minV, errMin := strconv.Atoi(minText)
		maxV, errMax := strconv.Atoi(maxText)
		if errMin != nil || errMax != nil || minV < 1 || maxV < 1 || minV > 4096 || maxV > 4096 || minV > maxV {
			return ErrPaddingScheme
		}
	}
	return nil
}

func paddingMD5(scheme string) string {
	// MD5 identifies the padding text for AnyTLS; it is not used as a password hash.
	sum := md5.Sum([]byte(scheme))
	return hex.EncodeToString(sum[:])
}

func canonicalPaddingScheme(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultAnyTLSPaddingScheme, nil
	}
	trimmed = strings.ReplaceAll(trimmed, "\r\n", "\n")
	trimmed = strings.Trim(trimmed, "\n")
	if err := validatePaddingScheme(trimmed); err != nil {
		return "", err
	}
	return trimmed, nil
}

func paddingRecordSizes(scheme string, pkt int) []int {
	if err := validatePaddingScheme(scheme); err != nil || pkt < 0 {
		return nil
	}
	var spec string
	var stop int
	for _, line := range strings.Split(scheme, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if key == "stop" {
			stop, _ = strconv.Atoi(value)
			continue
		}
		if key == strconv.Itoa(pkt) {
			spec = value
		}
	}
	if pkt >= stop || spec == "" {
		return nil
	}
	var sizes []int
	for _, part := range strings.Split(spec, ",") {
		if part == "c" {
			sizes = append(sizes, anytlsCheckMark)
			continue
		}
		minText, maxText, _ := strings.Cut(part, "-")
		minV, _ := strconv.Atoi(minText)
		maxV, _ := strconv.Atoi(maxText)
		if minV == maxV {
			sizes = append(sizes, minV)
			continue
		}
		span, err := rand.Int(rand.Reader, big.NewInt(int64(maxV-minV+1)))
		if err != nil {
			sizes = append(sizes, minV)
			continue
		}
		sizes = append(sizes, minV+int(span.Int64()))
	}
	return sizes
}

func anytlsPasswordHash(password []byte) [32]byte {
	return sha256.Sum256(password)
}

type anytlsIdentity struct {
	id   string
	hash [32]byte
}

func matchAnyTLSPassword(presented []byte, users []anytlsIdentity) string {
	if len(presented) != sha256.Size {
		return ""
	}
	matched := ""
	matches := 0
	for _, user := range users {
		if subtle.ConstantTimeCompare(presented, user.hash[:]) == 1 {
			matched = user.id
			matches++
		}
	}
	if matches != 1 {
		return ""
	}
	return matched
}

func writeAnyTLSClientHello(conn io.Writer, password []byte, scheme string) error {
	sizes := paddingRecordSizes(scheme, 0)
	pad := 0
	if len(sizes) > 0 && sizes[0] > 0 {
		pad = sizes[0]
	}
	buffer := make([]byte, 34+pad)
	hash := anytlsPasswordHash(password)
	copy(buffer, hash[:])
	binary.BigEndian.PutUint16(buffer[32:], uint16(pad))
	if pad > 0 {
		if _, err := rand.Read(buffer[34:]); err != nil {
			return err
		}
	}
	_, err := conn.Write(buffer)
	return err
}

func readAnyTLSClientHello(conn io.Reader, users []anytlsIdentity) (string, error) {
	header := make([]byte, 34)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	pad := int(binary.BigEndian.Uint16(header[32:]))
	if pad > 0 {
		if _, err := io.CopyN(io.Discard, conn, int64(pad)); err != nil {
			return "", err
		}
	}
	userID := matchAnyTLSPassword(header[:32], users)
	if userID == "" {
		return "", ErrAuthentication
	}
	return userID, nil
}

type anytlsSession struct {
	parent      context.Context
	conn        net.Conn
	isClient    bool
	padding     string
	sendPadding bool
	buffering   bool
	buffer      []byte
	pkt         uint32
	connMu      sync.Mutex

	mu          sync.Mutex
	streams     map[uint32]*anytlsStream
	nextID      uint32
	peerVersion int
	settings    bool
	closed      bool
	onStream    func(*anytlsStream)
	onPadding   func(string)
}

type anytlsStream struct {
	id           uint32
	sess         *anytlsSession
	incoming     chan []byte
	ctx          context.Context
	cancel       context.CancelFunc
	done         <-chan struct{}
	deliveryMu   sync.Mutex
	readBuf      []byte
	readMu       sync.Mutex
	readDeadline time.Time
	mu           sync.Mutex
	closed       bool
	once         sync.Once
}

type deadlineError struct{}

func (deadlineError) Error() string   { return "i/o deadline exceeded" }
func (deadlineError) Timeout() bool   { return true }
func (deadlineError) Temporary() bool { return true }

func (s *anytlsStream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(s.readBuf) > 0 {
		n := copy(p, s.readBuf)
		s.readBuf = s.readBuf[n:]
		if len(s.readBuf) == 0 {
			s.readBuf = nil
		}
		return n, nil
	}
	chunk, err := s.readChunk()
	if err != nil {
		return 0, err
	}
	n := copy(p, chunk)
	if n < len(chunk) {
		s.readBuf = chunk[n:]
	}
	return n, nil
}

// WriteTo forwards owned frames directly, including any tail left by a target
// address read. io.Copy can avoid a separate 32 KiB buffer for every stream.
func (s *anytlsStream) WriteTo(w io.Writer) (int64, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	var total int64
	for {
		if len(s.readBuf) == 0 {
			chunk, err := s.readChunk()
			if err == io.EOF {
				return total, nil
			}
			if err != nil {
				return total, err
			}
			s.readBuf = chunk
		}
		n, err := w.Write(s.readBuf)
		if n < 0 || n > len(s.readBuf) {
			return total, io.ErrShortWrite
		}
		total += int64(n)
		s.readBuf = s.readBuf[n:]
		if len(s.readBuf) == 0 {
			s.readBuf = nil
		} else if err == nil {
			err = io.ErrShortWrite
		}
		if err != nil {
			return total, err
		}
	}
}

func (s *anytlsStream) readChunk() ([]byte, error) {
	s.mu.Lock()
	deadline := s.readDeadline
	s.mu.Unlock()
	if deadline.IsZero() {
		chunk, ok := <-s.incoming
		if !ok {
			return nil, io.EOF
		}
		return chunk, nil
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case chunk, ok := <-s.incoming:
		if !ok {
			return nil, io.EOF
		}
		return chunk, nil
	case <-timer.C:
		return nil, deadlineError{}
	}
}

func (s *anytlsStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > 65535 {
			chunk = p[:65535]
		}
		if err := s.sess.writeData(s.id, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (s *anytlsStream) Close() error {
	var err error
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.sess.mu.Lock()
		delete(s.sess.streams, s.id)
		s.sess.mu.Unlock()
		s.closeIncoming()
		err = s.sess.writeFrame(anytlsCmdFIN, s.id, nil)
	})
	return err
}

func (s *anytlsStream) LocalAddr() net.Addr  { return s.sess.conn.LocalAddr() }
func (s *anytlsStream) RemoteAddr() net.Addr { return s.sess.conn.RemoteAddr() }
func (s *anytlsStream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.mu.Unlock()
	return s.sess.conn.SetWriteDeadline(t)
}
func (s *anytlsStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.mu.Unlock()
	return nil
}
func (s *anytlsStream) SetWriteDeadline(t time.Time) error {
	return s.sess.conn.SetWriteDeadline(t)
}

func (s *anytlsStream) deliver(data []byte) {
	s.deliveryMu.Lock()
	defer s.deliveryMu.Unlock()
	select {
	case <-s.done:
		return
	default:
	}
	// recvLoop transfers ownership of this frame; it never reuses its payload.
	select {
	case s.incoming <- data:
	case <-s.done:
	}
}

// Signal a blocked sender before closing the queue. Readers can drain frames
// queued before FIN without racing a send against close(incoming).
func (s *anytlsStream) closeIncoming() {
	s.cancel()
	s.deliveryMu.Lock()
	close(s.incoming)
	s.deliveryMu.Unlock()
}

func (s *anytlsSession) newStream(id uint32) *anytlsStream {
	parent := s.parent
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &anytlsStream{id: id, sess: s, incoming: make(chan []byte, 32), ctx: ctx, cancel: cancel, done: ctx.Done()}
}

func newServerAnyTLSSession(conn net.Conn, padding string, onStream func(*anytlsStream)) *anytlsSession {
	return &anytlsSession{
		conn:     conn,
		padding:  padding,
		streams:  map[uint32]*anytlsStream{},
		onStream: onStream,
	}
}

func startClientAnyTLSSession(conn net.Conn, password []byte, padding string, onPadding func(string)) (*anytlsSession, error) {
	if err := writeAnyTLSClientHello(conn, password, padding); err != nil {
		return nil, err
	}
	session := &anytlsSession{
		conn:        conn,
		isClient:    true,
		padding:     padding,
		sendPadding: true,
		buffering:   true,
		streams:     map[uint32]*anytlsStream{},
		onPadding:   onPadding,
	}
	settings := fmt.Sprintf("v=2\nclient=shadowsocks-server/%s\npadding-md5=%s\n", PluginVersion, paddingMD5(padding))
	if err := session.writeFrame(anytlsCmdSettings, 0, []byte(settings)); err != nil {
		return nil, err
	}
	go session.recvLoop()
	return session, nil
}

func (s *anytlsSession) openStream() (*anytlsStream, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, io.ErrClosedPipe
	}
	s.nextID++
	stream := s.newStream(s.nextID)
	s.streams[stream.id] = stream
	s.mu.Unlock()
	if err := s.writeFrame(anytlsCmdSYN, stream.id, nil); err != nil {
		_ = stream.Close()
		return nil, err
	}
	s.connMu.Lock()
	s.buffering = false
	s.connMu.Unlock()
	return stream, nil
}

func (s *anytlsSession) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	streams := s.streams
	s.streams = map[uint32]*anytlsStream{}
	s.mu.Unlock()
	err := s.conn.Close()
	for _, stream := range streams {
		stream.mu.Lock()
		stream.closed = true
		stream.mu.Unlock()
		stream.once.Do(stream.closeIncoming)
	}
	return err
}

func (s *anytlsSession) recvLoop() {
	defer s.Close()
	// Header-sized reads otherwise become individual managed-network RPCs.
	reader := bufio.NewReaderSize(s.conn, 4<<10)
	var header [anytlsHeaderSize]byte
	for {
		cmd, sid, data, err := readAnyTLSFrameHeader(reader, header[:])
		if err != nil {
			return
		}
		switch cmd {
		case anytlsCmdWaste:
		case anytlsCmdHeartRequest:
			if err := s.writeFrame(anytlsCmdHeartResponse, sid, nil); err != nil {
				return
			}
		case anytlsCmdHeartResponse, anytlsCmdSYNACK:
			if cmd == anytlsCmdSYNACK && len(data) > 0 {
				s.finishStream(sid)
			}
		case anytlsCmdPSH:
			s.mu.Lock()
			stream := s.streams[sid]
			s.mu.Unlock()
			if stream != nil && len(data) > 0 {
				stream.deliver(data)
			}
		case anytlsCmdFIN:
			s.finishStream(sid)
		case anytlsCmdSettings:
			if s.isClient {
				continue
			}
			fields := parseAnyTLSMap(data)
			s.mu.Lock()
			s.settings = true
			if version, err := strconv.Atoi(fields["v"]); err == nil && version >= 2 {
				s.peerVersion = version
			}
			padding := s.padding
			version := s.peerVersion
			s.mu.Unlock()
			if fields["padding-md5"] != paddingMD5(padding) {
				if err := s.writeFrame(anytlsCmdUpdatePaddingScheme, 0, []byte(padding)); err != nil {
					return
				}
			}
			if version >= 2 {
				if err := s.writeFrame(anytlsCmdServerSettings, 0, []byte("v=2\n")); err != nil {
					return
				}
			}
		case anytlsCmdSYN:
			if s.isClient {
				continue
			}
			s.mu.Lock()
			ready := s.settings
			s.mu.Unlock()
			if !ready {
				_ = s.writeFrame(anytlsCmdAlert, 0, []byte("client did not send its settings"))
				return
			}
			s.mu.Lock()
			_, exists := s.streams[sid]
			var stream *anytlsStream
			if !exists && !s.closed {
				stream = s.newStream(sid)
				s.streams[sid] = stream
			}
			handler := s.onStream
			s.mu.Unlock()
			if stream != nil && handler != nil {
				go handler(stream)
			}
		case anytlsCmdUpdatePaddingScheme:
			if s.isClient && s.onPadding != nil && len(data) > 0 && validatePaddingScheme(string(data)) == nil {
				s.onPadding(string(data))
			}
		case anytlsCmdServerSettings:
			if s.isClient {
				fields := parseAnyTLSMap(data)
				if version, err := strconv.Atoi(fields["v"]); err == nil {
					s.mu.Lock()
					s.peerVersion = version
					s.mu.Unlock()
				}
			}
		case anytlsCmdAlert:
			return
		default:
			if len(data) > 0 {
				continue
			}
		}
	}
}

func (s *anytlsSession) finishStream(sid uint32) {
	s.mu.Lock()
	stream := s.streams[sid]
	delete(s.streams, sid)
	s.mu.Unlock()
	if stream == nil {
		return
	}
	stream.once.Do(func() {
		stream.mu.Lock()
		stream.closed = true
		stream.mu.Unlock()
		stream.closeIncoming()
	})
}

func (s *anytlsSession) handshakeSuccess(stream *anytlsStream) error {
	s.mu.Lock()
	version := s.peerVersion
	s.mu.Unlock()
	if version < 2 || stream == nil {
		return nil
	}
	return s.writeFrame(anytlsCmdSYNACK, stream.id, nil)
}

func (s *anytlsSession) handshakeFailure(stream *anytlsStream, message string) error {
	s.mu.Lock()
	version := s.peerVersion
	s.mu.Unlock()
	if version < 2 || stream == nil {
		return nil
	}
	if message == "" {
		message = "closed"
	}
	return s.writeFrame(anytlsCmdSYNACK, stream.id, []byte(message))
}

func (s *anytlsSession) writeData(sid uint32, data []byte) error {
	return s.writeFrame(anytlsCmdPSH, sid, data)
}

func (s *anytlsSession) writeFrame(cmd byte, sid uint32, data []byte) error {
	if len(data) > 65535 {
		return ErrProtocol
	}
	buffer := borrowStreamWriteBuffer(anytlsHeaderSize + len(data))
	defer buffer.release()
	frame := buffer.data
	frame[0] = cmd
	binary.BigEndian.PutUint32(frame[1:], sid)
	binary.BigEndian.PutUint16(frame[5:], uint16(len(data)))
	copy(frame[anytlsHeaderSize:], data)
	_, err := s.writeConn(frame)
	return err
}

func (s *anytlsSession) writeConn(payload []byte) (int, error) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.buffering {
		s.buffer = append(s.buffer, payload...)
		return len(payload), nil
	}
	if len(s.buffer) > 0 {
		payload = append(append([]byte(nil), s.buffer...), payload...)
		s.buffer = nil
	}
	if s.sendPadding {
		s.pkt++
		stop := paddingStop(s.padding)
		if s.pkt < uint32(stop) {
			return s.writePadded(payload, paddingRecordSizes(s.padding, int(s.pkt)))
		}
		s.sendPadding = false
	}
	return s.conn.Write(payload)
}

func paddingStop(scheme string) int {
	for _, line := range strings.Split(scheme, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && key == "stop" {
			stop, _ := strconv.Atoi(value)
			return stop
		}
	}
	return 0
}

func (s *anytlsSession) writePadded(payload []byte, sizes []int) (int, error) {
	written := 0
	for _, size := range sizes {
		remain := len(payload)
		if size == anytlsCheckMark {
			if remain == 0 {
				break
			}
			continue
		}
		if remain > size {
			n, err := s.conn.Write(payload[:size])
			written += n
			if err != nil {
				return written, err
			}
			payload = payload[size:]
			continue
		}
		if remain > 0 {
			pad := size - remain - anytlsHeaderSize
			if pad > 0 {
				waste := make([]byte, anytlsHeaderSize+pad)
				waste[0] = anytlsCmdWaste
				binary.BigEndian.PutUint16(waste[5:], uint16(pad))
				payload = append(payload, waste...)
			}
			if _, err := s.conn.Write(payload); err != nil {
				return written, err
			}
			return written + remain, nil
		}
		waste := make([]byte, anytlsHeaderSize+size)
		waste[0] = anytlsCmdWaste
		binary.BigEndian.PutUint16(waste[5:], uint16(size))
		if _, err := s.conn.Write(waste); err != nil {
			return written, err
		}
	}
	if len(payload) == 0 {
		return written, nil
	}
	n, err := s.conn.Write(payload)
	return written + n, err
}

func readAnyTLSFrame(r io.Reader) (byte, uint32, []byte, error) {
	var header [anytlsHeaderSize]byte
	return readAnyTLSFrameHeader(r, header[:])
}

func readAnyTLSFrameHeader(r io.Reader, header []byte) (byte, uint32, []byte, error) {
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(header[5:]))
	var data []byte
	if length > 0 {
		data = make([]byte, length)
		if _, err := io.ReadFull(r, data); err != nil {
			return 0, 0, nil, err
		}
	}
	return header[0], binary.BigEndian.Uint32(header[1:5]), data, nil
}

func parseAnyTLSMap(raw []byte) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			continue
		}
		fields[key] = value
	}
	return fields
}

func isUoTv2Target(host string) bool {
	return strings.EqualFold(strings.Trim(host, "[]"), uotMagicV2)
}

func isLegacyUoTTarget(host string) bool {
	return strings.EqualFold(strings.Trim(host, "[]"), uotMagicLegacy)
}

func encodeSocksAddr(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, ErrProtocol
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, ErrProtocol
	}
	host = strings.Trim(host, "[]")
	var body []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			body = append([]byte{0x01}, v4...)
		} else {
			body = append([]byte{0x04}, ip.To16()...)
		}
	} else {
		if host == "" || len(host) > 255 {
			return nil, ErrProtocol
		}
		body = append([]byte{0x03, byte(len(host))}, host...)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(port))
	return body, nil
}

func readSocksAddr(r io.Reader) (string, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return "", err
	}
	var host string
	switch kind[0] {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", err
		}
		if n[0] == 0 {
			return "", ErrProtocol
		}
		buf := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		host = string(buf)
	default:
		return "", ErrProtocol
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func encodeSingAddr(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, ErrProtocol
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, ErrProtocol
	}
	host = strings.Trim(host, "[]")
	var body []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			body = append([]byte{0x00}, v4...)
		} else {
			body = append([]byte{0x01}, ip.To16()...)
		}
	} else {
		if host == "" || len(host) > 255 {
			return nil, ErrProtocol
		}
		body = append([]byte{0x02, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(body, uint16(port)), nil
}

func readSingAddr(r io.Reader) (string, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return "", err
	}
	var host string
	switch kind[0] {
	case 0x00:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x01:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x02:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", err
		}
		if n[0] == 0 {
			return "", ErrProtocol
		}
		buf := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		host = string(buf)
	default:
		return "", ErrProtocol
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

type uotRequest struct {
	isConnect   bool
	destination string
}

func writeUoTRequest(w io.Writer, isConnect bool, destination string) error {
	flag := byte(0)
	if isConnect {
		flag = 1
	}
	addr, err := encodeSocksAddr(destination)
	if err != nil {
		return err
	}
	_, err = w.Write(append([]byte{flag}, addr...))
	return err
}

func readUoTRequest(r io.Reader) (uotRequest, error) {
	var flag [1]byte
	if _, err := io.ReadFull(r, flag[:]); err != nil {
		return uotRequest{}, err
	}
	if flag[0] > 1 {
		return uotRequest{}, ErrProtocol
	}
	destination, err := readSocksAddr(r)
	if err != nil {
		return uotRequest{}, err
	}
	return uotRequest{isConnect: flag[0] == 1, destination: destination}, nil
}

func writeUoTPacket(w io.Writer, isConnect bool, destination string, payload []byte) error {
	if len(payload) > 65535 {
		return ErrProtocol
	}
	var header []byte
	if !isConnect {
		addr, err := encodeSingAddr(destination)
		if err != nil {
			return err
		}
		header = addr
	}
	header = binary.BigEndian.AppendUint16(header, uint16(len(payload)))
	if _, err := w.Write(append(header, payload...)); err != nil {
		return err
	}
	return nil
}

func readUoTPacket(r io.Reader, request uotRequest) (string, []byte, error) {
	destination := request.destination
	if !request.isConnect {
		addr, err := readSingAddr(r)
		if err != nil {
			return "", nil, err
		}
		destination = addr
	}
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return "", nil, err
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(length[:])))
	if len(payload) > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return "", nil, err
		}
	}
	return destination, payload, nil
}

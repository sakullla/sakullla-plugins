package shadowsocksserver

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// SIP002Account is the share material for one client. Traditional SS uses a
// single Password. SS2022 uses the instance ServerPSK plus a per-user IdentityPSK.
type SIP002Account struct {
	Method      string
	Password    string
	ServerPSK   string
	IdentityPSK string
	Host        string
	Port        int
}

// SIP002Share is an importable ss:// URI and a QR whose payload equals that URI.
type SIP002Share struct {
	Method   string
	Password string
	Host     string
	Port     int
	URI      string
	QR       QRCode
}

// QRCode encodes the SIP002 URI. Content is the QR payload and must equal URI.
type QRCode struct {
	Content string
	PNG     []byte
}

// GenerateSS2022Identity returns a pair of distinct canonical standard-Base64
// PSKs whose decoded length matches the SS2022 method.
func GenerateSS2022Identity(method string) (serverPSK, identityPSK string, err error) {
	return generateSS2022Identity(method, rand.Reader)
}

func generateSS2022Identity(method string, src io.Reader) (string, string, error) {
	keyLen, ok := ss2022KeyLen(method)
	if !ok {
		return "", "", ErrUnsupportedMethod
	}
	if src == nil {
		src = rand.Reader
	}
	server := make([]byte, keyLen)
	identity := make([]byte, keyLen)
	if _, err := io.ReadFull(src, server); err != nil {
		return "", "", err
	}
	for {
		if _, err := io.ReadFull(src, identity); err != nil {
			clear(server)
			return "", "", err
		}
		if !bytes.Equal(server, identity) {
			break
		}
	}
	serverPSK := base64.StdEncoding.EncodeToString(server)
	identityPSK := base64.StdEncoding.EncodeToString(identity)
	clear(server)
	clear(identity)
	if _, err := SS2022ClientPassword(method, []byte(serverPSK), []byte(identityPSK)); err != nil {
		return "", "", err
	}
	return serverPSK, identityPSK, nil
}

// BuildSIP002 projects an importable SIP002 URI and a QR with the same content.
// SS2022 userinfo is percent-encoded method:password and is not Base64URL.
func BuildSIP002(account SIP002Account) (SIP002Share, error) {
	password, err := sip002ClientPassword(account)
	if err != nil {
		return SIP002Share{}, err
	}
	uri, err := SIP002URI(account.Method, password, account.Host, account.Port)
	if err != nil {
		return SIP002Share{}, err
	}
	qr, err := encodeSIP002QR(uri)
	if err != nil {
		return SIP002Share{}, err
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return SIP002Share{}, ErrInvalid
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		return SIP002Share{}, ErrInvalid
	}
	return SIP002Share{
		Method:   account.Method,
		Password: password,
		Host:     parsed.Hostname(),
		Port:     port,
		URI:      uri,
		QR:       qr,
	}, nil
}

func sip002ClientPassword(account SIP002Account) (string, error) {
	if strings.HasPrefix(account.Method, "2022-") {
		if account.Password != "" || account.ServerPSK == "" || account.IdentityPSK == "" {
			return "", ErrInvalid
		}
		return SS2022ClientPassword(account.Method, []byte(account.ServerPSK), []byte(account.IdentityPSK))
	}
	if account.Password == "" || account.ServerPSK != "" || account.IdentityPSK != "" {
		return "", ErrInvalid
	}
	return account.Password, nil
}

// SS2022ClientPassword returns the SIP002 password serverPSK:userPSK. Both
// values must be canonical standard Base64 of the method key length and differ.
func SS2022ClientPassword(method string, serverPSK, userPSK []byte) (string, error) {
	server, err := decodeCanonicalPSK(method, string(serverPSK))
	if err != nil {
		return "", err
	}
	user, err := decodeCanonicalPSK(method, string(userPSK))
	if err != nil {
		clear(server)
		return "", err
	}
	same := bytes.Equal(server, user)
	clear(server)
	clear(user)
	if same {
		return "", ErrInvalid
	}
	return string(serverPSK) + ":" + string(userPSK), nil
}

func decodeCanonicalPSK(method, encoded string) ([]byte, error) {
	keyLen, ok := ss2022KeyLen(method)
	if !ok {
		return nil, ErrUnsupportedMethod
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != keyLen || base64.StdEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, ErrInvalid
	}
	return decoded, nil
}

func ss2022KeyLen(method string) (int, bool) {
	if !strings.HasPrefix(method, "2022-") {
		return 0, false
	}
	n, ok := supportedMethods[method]
	return n, ok
}

func sip002HostPort(host string, port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", ErrInvalid
	}
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") {
		if !strings.HasSuffix(host, "]") || len(host) < 4 {
			return "", ErrInvalid
		}
		host = host[1 : len(host)-1]
	}
	if host == "" {
		return "", ErrInvalid
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else if strings.ContainsAny(host, " /?#@:[]\x00\r\n") {
		return "", ErrInvalid
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func encodeSIP002QR(content string) (QRCode, error) {
	if content == "" || SIP002QRContent(content) != content {
		return QRCode{}, ErrInvalid
	}
	pngBytes, err := encodeQRPNG(content)
	if err != nil {
		return QRCode{}, err
	}
	return QRCode{Content: SIP002QRContent(content), PNG: pngBytes}, nil
}

const (
	qrMaxVersion = 16
	qrQuietZone  = 4
	qrModulePx   = 4
	qrECCLevelM  = 0
)

type qrBlockLayout struct {
	ecPerBlock int
	g1Blocks   int
	g1Data     int
	g2Blocks   int
	g2Data     int
}

// ECC-M block layout for versions 1-16 (ISO/IEC 18004 Table 9).
var qrMLayout = [qrMaxVersion + 1]qrBlockLayout{
	1:  {10, 1, 16, 0, 0},
	2:  {16, 1, 28, 0, 0},
	3:  {26, 1, 44, 0, 0},
	4:  {18, 2, 32, 0, 0},
	5:  {24, 2, 43, 0, 0},
	6:  {16, 4, 27, 0, 0},
	7:  {18, 4, 31, 0, 0},
	8:  {22, 2, 38, 2, 39},
	9:  {22, 3, 36, 2, 37},
	10: {26, 4, 43, 1, 44},
	11: {30, 1, 50, 4, 51},
	12: {22, 6, 36, 2, 37},
	13: {22, 8, 37, 1, 38},
	14: {24, 4, 40, 5, 41},
	15: {24, 5, 41, 5, 42},
	16: {28, 7, 45, 3, 46},
}

var qrAlignPos = [qrMaxVersion + 1][]int{
	2:  {6, 18},
	3:  {6, 22},
	4:  {6, 26},
	5:  {6, 30},
	6:  {6, 34},
	7:  {6, 22, 38},
	8:  {6, 24, 42},
	9:  {6, 26, 46},
	10: {6, 28, 50},
	11: {6, 30, 54},
	12: {6, 32, 58},
	13: {6, 34, 62},
	14: {6, 26, 46, 66},
	15: {6, 26, 48, 70},
	16: {6, 26, 50, 74},
}

func qrDataCodewords(version int) int {
	layout := qrMLayout[version]
	return layout.g1Blocks*layout.g1Data + layout.g2Blocks*layout.g2Data
}

func qrByteCapacity(version int) int {
	countBits := 8
	if version >= 10 {
		countBits = 16
	}
	return (qrDataCodewords(version)*8 - 4 - countBits) / 8
}

func qrRemainderBits(version int) int {
	switch {
	case version >= 2 && version <= 6:
		return 7
	case version >= 14:
		return 3
	default:
		return 0
	}
}

func encodeQRPNG(content string) ([]byte, error) {
	version := 0
	for v := 1; v <= qrMaxVersion; v++ {
		if len(content) <= qrByteCapacity(v) {
			version = v
			break
		}
	}
	if version == 0 {
		return nil, ErrInvalid
	}
	data := qrEncodeData(content, version)
	codewords := qrInterleave(data, version)
	size := 21 + 4*(version-1)
	modules := make([][]bool, size)
	reserved := make([][]bool, size)
	for i := range modules {
		modules[i] = make([]bool, size)
		reserved[i] = make([]bool, size)
	}
	qrPlaceFunctionPatterns(modules, reserved, version)
	qrPlaceData(modules, reserved, qrCodewordBits(codewords, qrRemainderBits(version)))
	mask := qrSelectMask(modules, reserved)
	qrApplyMask(modules, reserved, mask)
	qrPlaceFormat(modules, reserved, mask)
	if version >= 7 {
		qrPlaceVersion(modules, reserved, version)
	}
	return qrPNG(modules)
}

func qrEncodeData(content string, version int) []byte {
	countBits := 8
	if version >= 10 {
		countBits = 16
	}
	capacity := qrDataCodewords(version)
	bits := make([]bool, 0, capacity*8)
	bits = qrAppendBits(bits, 0b0100, 4)
	bits = qrAppendBits(bits, len(content), countBits)
	for i := 0; i < len(content); i++ {
		bits = qrAppendBits(bits, int(content[i]), 8)
	}
	remain := capacity*8 - len(bits)
	if remain > 4 {
		remain = 4
	}
	bits = qrAppendBits(bits, 0, remain)
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	for i := 0; len(bits)/8 < capacity; i++ {
		if i%2 == 0 {
			bits = qrAppendBits(bits, 0xEC, 8)
		} else {
			bits = qrAppendBits(bits, 0x11, 8)
		}
	}
	out := make([]byte, capacity)
	for i := range out {
		var b byte
		for j := 0; j < 8; j++ {
			if bits[i*8+j] {
				b |= 1 << (7 - j)
			}
		}
		out[i] = b
	}
	return out
}

func qrInterleave(data []byte, version int) []byte {
	layout := qrMLayout[version]
	blocks := make([][]byte, 0, layout.g1Blocks+layout.g2Blocks)
	offset := 0
	appendGroup := func(count, dataLen int) {
		for i := 0; i < count; i++ {
			block := make([]byte, dataLen+layout.ecPerBlock)
			copy(block, data[offset:offset+dataLen])
			copy(block[dataLen:], qrReedSolomon(data[offset:offset+dataLen], layout.ecPerBlock))
			blocks = append(blocks, block)
			offset += dataLen
		}
	}
	appendGroup(layout.g1Blocks, layout.g1Data)
	appendGroup(layout.g2Blocks, layout.g2Data)
	maxData := layout.g1Data
	if layout.g2Data > maxData {
		maxData = layout.g2Data
	}
	out := make([]byte, 0, len(data)+(layout.g1Blocks+layout.g2Blocks)*layout.ecPerBlock)
	for i := 0; i < maxData; i++ {
		for _, block := range blocks {
			dataLen := len(block) - layout.ecPerBlock
			if i < dataLen {
				out = append(out, block[i])
			}
		}
	}
	for i := 0; i < layout.ecPerBlock; i++ {
		for _, block := range blocks {
			out = append(out, block[len(block)-layout.ecPerBlock+i])
		}
	}
	return out
}

func qrCodewordBits(codewords []byte, remainder int) []bool {
	bits := make([]bool, 0, len(codewords)*8+remainder)
	for _, b := range codewords {
		for i := 7; i >= 0; i-- {
			bits = append(bits, b&(1<<uint(i)) != 0)
		}
	}
	return append(bits, make([]bool, remainder)...)
}

func qrAppendBits(bits []bool, value, width int) []bool {
	for i := width - 1; i >= 0; i-- {
		bits = append(bits, value&(1<<uint(i)) != 0)
	}
	return bits
}

func qrPlaceFunctionPatterns(modules, reserved [][]bool, version int) {
	n := len(modules)
	qrFinder(modules, reserved, 0, 0)
	qrFinder(modules, reserved, n-7, 0)
	qrFinder(modules, reserved, 0, n-7)
	qrSeparator(reserved, 0, 7, 8, 1)
	qrSeparator(reserved, 7, 0, 1, 8)
	qrSeparator(reserved, 0, n-8, 8, 1)
	qrSeparator(reserved, 7, n-8, 1, 8)
	qrSeparator(reserved, n-8, 7, 8, 1)
	qrSeparator(reserved, n-8, 0, 1, 8)
	for i := 8; i < n-8; i++ {
		on := i%2 == 0
		qrSet(modules, reserved, 6, i, on)
		qrSet(modules, reserved, i, 6, on)
	}
	for _, r := range qrAlignPos[version] {
		for _, c := range qrAlignPos[version] {
			if qrFinderCorner(n, r, c) {
				continue
			}
			qrAlignment(modules, reserved, r, c)
		}
	}
	qrReserveFormat(reserved)
	if version >= 7 {
		qrReserveVersion(reserved)
	}
	qrSet(modules, reserved, 4*version+9, 8, true)
}

func qrFinderCorner(n, r, c int) bool {
	return r <= 6 && c <= 6 || r <= 6 && c >= n-7 || r >= n-7 && c <= 6
}

func qrFinder(modules, reserved [][]bool, row, col int) {
	for r := -1; r <= 7; r++ {
		for c := -1; c <= 7; c++ {
			rr, cc := row+r, col+c
			if rr < 0 || cc < 0 || rr >= len(modules) || cc >= len(modules) {
				continue
			}
			on := r >= 0 && r <= 6 && c >= 0 && c <= 6 && (r == 0 || r == 6 || c == 0 || c == 6 || r >= 2 && r <= 4 && c >= 2 && c <= 4)
			qrSet(modules, reserved, rr, cc, on)
		}
	}
}

func qrAlignment(modules, reserved [][]bool, row, col int) {
	for r := -2; r <= 2; r++ {
		for c := -2; c <= 2; c++ {
			on := r == -2 || r == 2 || c == -2 || c == 2 || r == 0 && c == 0
			qrSet(modules, reserved, row+r, col+c, on)
		}
	}
}

func qrSeparator(reserved [][]bool, row, col, rows, cols int) {
	for r := 0; r < rows; r++ {
		for c := 0; c < cols; c++ {
			rr, cc := row+r, col+c
			if rr >= 0 && cc >= 0 && rr < len(reserved) && cc < len(reserved) {
				reserved[rr][cc] = true
			}
		}
	}
}

func qrReserveFormat(reserved [][]bool) {
	n := len(reserved)
	for i := 0; i < 9; i++ {
		reserved[8][i] = true
		reserved[i][8] = true
	}
	for i := 0; i < 8; i++ {
		reserved[8][n-1-i] = true
		reserved[n-1-i][8] = true
	}
}

func qrReserveVersion(reserved [][]bool) {
	n := len(reserved)
	for i := 0; i < 6; i++ {
		for j := 0; j < 3; j++ {
			reserved[i][n-11+j] = true
			reserved[n-11+j][i] = true
		}
	}
}

func qrSet(modules, reserved [][]bool, r, c int, on bool) {
	modules[r][c] = on
	reserved[r][c] = true
}

func qrPlaceData(modules, reserved [][]bool, bits []bool) {
	n := len(modules)
	bit := 0
	up := true
	for col := n - 1; col > 0; col -= 2 {
		if col == 6 {
			col--
		}
		for i := 0; i < n; i++ {
			row := i
			if up {
				row = n - 1 - i
			}
			for _, c := range []int{col, col - 1} {
				if reserved[row][c] {
					continue
				}
				if bit < len(bits) {
					modules[row][c] = bits[bit]
					bit++
				}
			}
		}
		up = !up
	}
}

func qrMaskAt(mask, r, c int) bool {
	switch mask {
	case 0:
		return (r+c)%2 == 0
	case 1:
		return r%2 == 0
	case 2:
		return c%3 == 0
	case 3:
		return (r+c)%3 == 0
	case 4:
		return (r/2+c/3)%2 == 0
	case 5:
		return (r*c)%2+(r*c)%3 == 0
	case 6:
		return ((r*c)%2+(r*c)%3)%2 == 0
	default:
		return ((r+c)%2+(r*c)%3)%2 == 0
	}
}

func qrApplyMask(modules, reserved [][]bool, mask int) {
	for r := range modules {
		for c := range modules[r] {
			if !reserved[r][c] && qrMaskAt(mask, r, c) {
				modules[r][c] = !modules[r][c]
			}
		}
	}
}

func qrSelectMask(modules, reserved [][]bool) int {
	bestMask, bestScore := 0, int(^uint(0)>>1)
	for mask := 0; mask < 8; mask++ {
		qrApplyMask(modules, reserved, mask)
		score := qrPenalty(modules)
		qrApplyMask(modules, reserved, mask)
		if score < bestScore {
			bestMask, bestScore = mask, score
		}
	}
	return bestMask
}

func qrPenalty(modules [][]bool) int {
	n := len(modules)
	score := 0
	dark := 0
	for r := 0; r < n; r++ {
		runColor, run := modules[r][0], 1
		for c := 0; c < n; c++ {
			if modules[r][c] {
				dark++
			}
			if c == 0 {
				continue
			}
			if modules[r][c] == runColor {
				run++
				continue
			}
			if run >= 5 {
				score += run - 2
			}
			runColor, run = modules[r][c], 1
		}
		if run >= 5 {
			score += run - 2
		}
	}
	for c := 0; c < n; c++ {
		runColor, run := modules[0][c], 1
		for r := 1; r < n; r++ {
			if modules[r][c] == runColor {
				run++
				continue
			}
			if run >= 5 {
				score += run - 2
			}
			runColor, run = modules[r][c], 1
		}
		if run >= 5 {
			score += run - 2
		}
	}
	for r := 0; r < n-1; r++ {
		for c := 0; c < n-1; c++ {
			v := modules[r][c]
			if modules[r][c+1] == v && modules[r+1][c] == v && modules[r+1][c+1] == v {
				score += 3
			}
		}
	}
	for r := 0; r < n; r++ {
		for c := 0; c < n-10; c++ {
			if qrFinderRun(modules, r, c, 0, 1) {
				score += 40
			}
		}
	}
	for c := 0; c < n; c++ {
		for r := 0; r < n-10; r++ {
			if qrFinderRun(modules, r, c, 1, 0) {
				score += 40
			}
		}
	}
	total := n * n
	deviation := dark*200/total - 100
	if deviation < 0 {
		deviation = -deviation
	}
	score += (deviation / 5) * 10
	return score
}

func qrFinderRun(modules [][]bool, r, c, dr, dc int) bool {
	pattern := [11]bool{true, false, true, true, true, false, true, false, false, false, false}
	alt := [11]bool{false, false, false, false, true, false, true, true, true, false, true}
	match, matchAlt := true, true
	for i := 0; i < 11; i++ {
		v := modules[r+i*dr][c+i*dc]
		if v != pattern[i] {
			match = false
		}
		if v != alt[i] {
			matchAlt = false
		}
	}
	return match || matchAlt
}

func qrPlaceFormat(modules, reserved [][]bool, mask int) {
	bits := qrFormatBits(mask)
	n := len(modules)
	for i := 0; i < 15; i++ {
		on := bits&(1<<uint(i)) != 0
		r, c := qrFormatTL(i)
		modules[r][c] = on
		if i < 8 {
			modules[n-1-i][8] = on
		} else {
			modules[8][n-15+i] = on
		}
	}
	_ = reserved
}

func qrFormatTL(i int) (int, int) {
	switch {
	case i < 6:
		return 8, i
	case i < 8:
		return 8, i + 1
	case i == 8:
		return 7, 8
	default:
		return 14 - i, 8
	}
}

func qrFormatBits(mask int) int {
	data := qrECCLevelM<<3 | mask
	bits := data << 10
	for i := 14; i >= 10; i-- {
		if bits&(1<<uint(i)) != 0 {
			bits ^= 0x537 << uint(i-10)
		}
	}
	return (data<<10 | bits) ^ 0x5412
}

func qrPlaceVersion(modules, reserved [][]bool, version int) {
	bits := qrVersionBits(version)
	n := len(modules)
	for i := 0; i < 18; i++ {
		on := bits&(1<<uint(i)) != 0
		modules[i/3][n-11+i%3] = on
		modules[n-11+i%3][i/3] = on
	}
	_ = reserved
}

func qrVersionBits(version int) int {
	bits := version << 12
	for i := 17; i >= 12; i-- {
		if bits&(1<<uint(i)) != 0 {
			bits ^= 0x1F25 << uint(i-12)
		}
	}
	return version<<12 | bits
}

func qrPNG(modules [][]bool) ([]byte, error) {
	n := len(modules)
	size := (n + qrQuietZone*2) * qrModulePx
	img := image.NewGray(image.Rect(0, 0, size, size))
	white := color.Gray{Y: 255}
	black := color.Gray{Y: 0}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			img.SetGray(x, y, white)
		}
	}
	for r := 0; r < n; r++ {
		for c := 0; c < n; c++ {
			if !modules[r][c] {
				continue
			}
			x0 := (c + qrQuietZone) * qrModulePx
			y0 := (r + qrQuietZone) * qrModulePx
			for y := 0; y < qrModulePx; y++ {
				for x := 0; x < qrModulePx; x++ {
					img.SetGray(x0+x, y0+y, black)
				}
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var (
	qrGFOnce sync.Once
	qrExp    [512]byte
	qrLog    [256]byte
)

func qrEnsureGF() {
	qrGFOnce.Do(func() {
		x := 1
		for i := 0; i < 255; i++ {
			qrExp[i] = byte(x)
			qrLog[x] = byte(i)
			x <<= 1
			if x&0x100 != 0 {
				x ^= 0x11d
			}
		}
		for i := 255; i < 512; i++ {
			qrExp[i] = qrExp[i-255]
		}
	})
}

func qrMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return qrExp[int(qrLog[a])+int(qrLog[b])]
}

func qrReedSolomon(data []byte, degree int) []byte {
	qrEnsureGF()
	gen := []byte{1}
	for i := 0; i < degree; i++ {
		next := make([]byte, len(gen)+1)
		copy(next, gen)
		c := qrExp[i]
		for j := 0; j < len(gen); j++ {
			next[j+1] ^= qrMul(gen[j], c)
		}
		gen = next
	}
	buf := make([]byte, len(data)+degree)
	copy(buf, data)
	for i := 0; i < len(data); i++ {
		coef := buf[i]
		if coef == 0 {
			continue
		}
		for j := 0; j < len(gen); j++ {
			buf[i+j] ^= qrMul(gen[j], coef)
		}
	}
	return buf[len(data):]
}

// Package rlpx implements the RLPx transport protocol.
package rlpx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/ethereum/go-ethereum/cryptod"
	"github.com/ethereum/go-ethereum/cryptok"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/golang/snappy"
)

// Conn is an RLPx network connection.
type Conn struct {
	dialDest  *cryptod.PublicKey
	conn      net.Conn
	handshake *handshakeState
	snappy    bool
	secrets   Secrets
}

// Keep same....
type handshakeState struct {
	enc cipher.Stream
	dec cipher.Stream

	macCipher  cipher.Block
	egressMAC  hash.Hash
	ingressMAC hash.Hash
}

// Constants for the handshake.
const (
	maxUint24   = int(^uint32(0) >> 8)
	sskLen      = 32
	sigLen      = 4627 // ML-DSA-87 signature size
	pubLen      = 2592 // ML-DSA-87 public key size
	shaLen      = 32
	kyberPubLen = 1568                                       // Kyber-1024 public key size
	authMsgLen  = sigLen + pubLen + kyberPubLen + shaLen + 1 //4627 + 2592 + 1568 + 32 + 1 = 8820.

	//authMsgLen  = sigLen + shaLen + pubLen + shaLen + 1
	authRespLen    = pubLen + kyberPubLen + shaLen + 1 //2592 + 1568 + 32 + 1 = 4193
	encAuthMsgLen  = authMsgLen
	encAuthRespLen = authRespLen
)

var (
	zeroHeader              = []byte{0xC2, 0x80, 0x80}
	zero16                  = make([]byte, 16)
	errPlainMessageTooLarge = errors.New("message length >= 16MB")
)

// Secrets represents the connection secrets.
type Secrets struct {
	AES, MAC, SharedSecret []byte
	remoteKyberPub         *cryptok.PublicKey
	remote                 *cryptod.PublicKey // Added to store ML-DSA-87 remote public key
	EgressMAC, IngressMAC  hash.Hash          // Added for handshakeState
}

// GetSecrets returns the connection secrets.
func (c *Conn) GetSecrets() Secrets {
	return c.secrets
}

// encHandshake contains the state of the encryption handshake.
type encHandshake struct {
	initiator            bool
	remote               *cryptod.PublicKey
	initNonce, respNonce []byte
	randomPrivKey        *cryptod.PrivateKey
	remoteRandomPub      *cryptod.PublicKey
	remoteKyberPub       *cryptok.PublicKey
	sharedSecret         []byte // Store shared secret
	kyberCiphertext      []byte // Store ciphertext for responder
}

type authMsgV4 struct {
	gotPlain          bool
	Signature         [4627]byte // ML-DSA-87 signature
	InitiatorPubkey   [2592]byte // ML-DSA-87 public key
	InitiatorKyberPub [1568]byte // Kyber-1024 public key
	Nonce             [shaLen]byte
	Version           uint
	Rest              []rlp.RawValue `rlp:"tail"`
}

type authRespV4 struct {
	RandomPubkey    [2592]byte // ML-DSA-87 public key
	KyberCiphertext [1568]byte // Kyber-1024 ciphertext
	Nonce           [shaLen]byte
	Version         uint
	Rest            []rlp.RawValue `rlp:"tail"`
}

// NewConn wraps the given network connection.
func NewConn(conn net.Conn, dialDest *cryptod.PublicKey) *Conn {
	return &Conn{
		dialDest: dialDest,
		conn:     conn,
	}
}

// SetSnappy enables or disables snappy compression.
func (c *Conn) SetSnappy(snappy bool) {
	c.snappy = snappy
}

// SetReadDeadline sets the deadline for read operations.
func (c *Conn) SetReadDeadline(time time.Time) error {
	return c.conn.SetReadDeadline(time)
}

// SetWriteDeadline sets the deadline for write operations.
func (c *Conn) SetWriteDeadline(time time.Time) error {
	return c.conn.SetWriteDeadline(time)
}

// SetDeadline sets the deadline for read and write operations.
func (c *Conn) SetDeadline(time time.Time) error {
	return c.conn.SetDeadline(time)
}

// Read reads a message from the connection.
func (c *Conn) Read() (code uint64, data []byte, wireSize int, err error) {
	if c.handshake == nil {
		panic("can't ReadMsg before handshake")
	}

	frame, err := c.handshake.readFrame(c.conn)
	if err != nil {
		return 0, nil, 0, err
	}
	code, data, err = rlp.SplitUint64(frame)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("invalid message code: %v", err)
	}
	wireSize = len(data)

	if c.snappy {
		var actualSize int
		actualSize, err = snappy.DecodedLen(data)
		if err != nil {
			return code, nil, 0, err
		}
		if actualSize > maxUint24 {
			return code, nil, 0, errPlainMessageTooLarge
		}
		data, err = snappy.Decode(nil, data)
	}
	return code, data, wireSize, err
}

func (h *handshakeState) readFrame(conn io.Reader) ([]byte, error) {
	headbuf := make([]byte, 32)
	if _, err := io.ReadFull(conn, headbuf); err != nil {
		return nil, err
	}
	if len(headbuf) < 32 {
		return nil, fmt.Errorf("invalid header length")
	}
	shouldMAC := updateMAC(h.ingressMAC, h.macCipher, headbuf[:16])
	if !hmac.Equal(shouldMAC, headbuf[16:]) {
		return nil, errors.New("bad header MAC")
	}
	h.dec.XORKeyStream(headbuf[:16], headbuf[:16])
	fsize := readInt24(headbuf)
	var rsize = fsize
	if padding := fsize % 16; padding > 0 {
		rsize += 16 - padding
	}
	framebuf := make([]byte, rsize)
	if _, err := io.ReadFull(conn, framebuf); err != nil {
		return nil, err
	}
	h.ingressMAC.Write(framebuf)
	fmacseed := h.ingressMAC.Sum(nil)
	if _, err := io.ReadFull(conn, headbuf[:16]); err != nil {
		return nil, err
	}
	shouldMAC = updateMAC(h.ingressMAC, h.macCipher, fmacseed)
	if !hmac.Equal(shouldMAC, headbuf[:16]) {
		return nil, errors.New("bad frame MAC")
	}
	h.dec.XORKeyStream(framebuf, framebuf)
	return framebuf[:fsize], nil
}

// Write writes a message to the connection.
func (c *Conn) Write(code uint64, data []byte) (uint32, error) {
	if c.handshake == nil {
		panic("can't WriteMsg before handshake")
	}
	if len(data) > maxUint24 {
		return 0, errPlainMessageTooLarge
	}
	if c.snappy {
		data = snappy.Encode(nil, data)
	}
	wireSize := uint32(len(data))
	err := c.handshake.writeFrame(c.conn, code, data)
	return wireSize, err
}

func (h *handshakeState) writeFrame(conn io.Writer, code uint64, data []byte) error {
	ptype, _ := rlp.EncodeToBytes(code)

	headbuf := make([]byte, 32)
	fsize := len(ptype) + len(data)
	if fsize > maxUint24 {
		return errPlainMessageTooLarge
	}
	putInt24(uint32(fsize), headbuf)
	copy(headbuf[3:], zeroHeader)
	h.enc.XORKeyStream(headbuf[:16], headbuf[:16])
	copy(headbuf[16:], updateMAC(h.egressMAC, h.macCipher, headbuf[:16]))
	if _, err := conn.Write(headbuf); err != nil {
		return err
	}

	tee := cipher.StreamWriter{S: h.enc, W: io.MultiWriter(conn, h.egressMAC)}
	if _, err := tee.Write(ptype); err != nil {
		return err
	}
	if _, err := tee.Write(data); err != nil {
		return err
	}
	if padding := fsize % 16; padding > 0 {
		if _, err := tee.Write(zero16[:16-padding]); err != nil {
			return err
		}
	}

	fmacseed := h.egressMAC.Sum(nil)
	mac := updateMAC(h.egressMAC, h.macCipher, fmacseed)
	_, err := conn.Write(mac)
	return err
}

func readInt24(b []byte) uint32 {
	return uint32(b[2]) | uint32(b[1])<<8 | uint32(b[0])<<16
}

func putInt24(v uint32, b []byte) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

func updateMAC(mac hash.Hash, block cipher.Block, seed []byte) []byte {
	aesbuf := make([]byte, aes.BlockSize)
	block.Encrypt(aesbuf, mac.Sum(nil))
	for i := range aesbuf {
		aesbuf[i] ^= seed[i]
	}
	mac.Write(aesbuf)
	return mac.Sum(nil)[:16]
}

type handshakeOptions struct {
	kyberPrv *cryptok.PrivateKey
	kyberPub *cryptok.PublicKey
}

type HandshakeOption func(*handshakeOptions)

func WithKyberPrv(kyberPrv *cryptok.PrivateKey, kyberPub *cryptok.PublicKey) HandshakeOption {
	return func(opts *handshakeOptions) {
		opts.kyberPrv = kyberPrv
		opts.kyberPub = kyberPub
	}
}

type HandshakeResult struct {
	PubKey   *cryptod.PublicKey
	KyberKey *cryptok.PublicKey
	Err      error
}

// Handshake performs the handshake.
func (c *Conn) Handshake(prv *cryptod.PrivateKey, kyberprvOpt ...HandshakeOption) HandshakeResult {
	var (
		sec Secrets
		err error
	)
	options := &handshakeOptions{}
	for _, opt := range kyberprvOpt {
		opt(options)
	}
	if options.kyberPrv == nil {
		return HandshakeResult{Err: fmt.Errorf("kyber private key is missing in handshake")}
	}

	kyberPub := options.kyberPrv.Public().(*cryptok.PublicKey)
	// pkBytes, _ := options.kyberPrv.MarshalBinary()
	// fmt.Printf("🔹 [Handshake] Kyber Private Key Size: %d, Key: %x\n", len(pkBytes))
	//kyberPubBytes, _ := kyberPub.MarshalBinary()
	//fmt.Printf("🔹 [Handshake] Kyber Public Key: %x\n", kyberPubBytes)

	if c.dialDest != nil {
		sec, err = initiatorEncHandshake(c.conn, prv, c.dialDest, options.kyberPrv, kyberPub)
	} else {
		sec, err = receiverEncHandshake(c.conn, prv, options.kyberPrv)
	}

	if err != nil {
		return HandshakeResult{Err: err}
	}

	c.InitWithSecrets(sec)
	if c.handshake == nil {
		return HandshakeResult{Err: fmt.Errorf("handshake state not initialized")}
	}
	c.secrets = sec

	// //var kyberPubBytesFinal []byte
	// if sec.remoteKyberPub != nil {
	// 	//kyberPubBytesFinal, err = sec.remoteKyberPub.MarshalBinary()
	// 	if err != nil {
	// 	}
	// } else {
	// }
	// fmt.Printf("🔹 [Handshake] Completed - Remote PubKey: %x, KyberKey: %x\n", exportPubkey(sec.remote), kyberPubBytesFinal)
	return HandshakeResult{
		PubKey:   sec.remote,
		KyberKey: sec.remoteKyberPub,
	}
}
func receiverEncHandshake(conn io.ReadWriter, prv *cryptod.PrivateKey, kyberPrv *cryptok.PrivateKey) (s Secrets, err error) {
	h := &encHandshake{initiator: false}
	authMsg := new(authMsgV4)
	authPacket, err := readHandshakeMsg(authMsg, encAuthMsgLen, prv, kyberPrv, conn)
	if err != nil {
		return s, fmt.Errorf("failed to read auth message: %v", err)
	}
	if err := h.handleAuthMsg(authMsg, kyberPrv); err != nil {
		return s, fmt.Errorf("failed to handle auth message: %v", err)
	}

	authRespMsg, err := h.makeAuthResp(kyberPrv)
	if err != nil {
		return s, fmt.Errorf("failed to create auth response: %v", err)
	}

	authRespPacket, err := sealEIP8(authRespMsg, h)
	if err != nil {
		return s, err
	}

	if _, err = conn.Write(authRespPacket); err != nil {
		return s, fmt.Errorf("failed to send auth response: %v", err)
	}

	s, err = h.secrets(authPacket, authRespPacket)
	if err != nil {
		return s, err
	}
	s.SharedSecret = h.sharedSecret
	s.remoteKyberPub = h.remoteKyberPub
	return s, nil
}

// InitWithSecrets injects connection secrets.
func (c *Conn) InitWithSecrets(sec Secrets) {
	if c.handshake != nil {
		panic("can't handshake twice")
	}
	// Validate key lengths
	if len(sec.AES) != 16 {
		panic(fmt.Sprintf("invalid AES key length: got %d, want 16", len(sec.AES)))
	}
	// Note: sec.MAC length can vary for HMAC-SHA256, but should be at least 16
	if len(sec.MAC) < 16 {
		panic(fmt.Sprintf("invalid MAC key length: got %d, want at least 16", len(sec.MAC)))
	}
	if sec.EgressMAC == nil || sec.IngressMAC == nil {
		panic("nil EgressMAC or IngressMAC in Secrets")
	}
	encc, err := aes.NewCipher(sec.AES)
	if err != nil {
		panic("invalid AES secret: " + err.Error())
	}
	macc, err := aes.NewCipher(sec.MAC[:16]) // Use first 16 bytes of MAC key
	if err != nil {
		panic("invalid MAC secret: " + err.Error())
	}
	iv := make([]byte, encc.BlockSize())
	c.handshake = &handshakeState{
		enc:        cipher.NewCTR(encc, iv),
		dec:        cipher.NewCTR(encc, iv),
		macCipher:  macc,
		egressMAC:  sec.EgressMAC,
		ingressMAC: sec.IngressMAC,
	}
}

// Close closes the underlying connection.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// receiverEncHandshake negotiates a session token on the listening side.

func (h *encHandshake) makeAuthResp(kyberPrv *cryptok.PrivateKey) (*authRespV4, error) {
	h.respNonce = make([]byte, shaLen)
	if _, err := rand.Read(h.respNonce); err != nil {
		return nil, err
	}

	pubKey := h.randomPrivKey.Public().(*cryptod.PublicKey)
	pubKeyBytes := cryptod.FromMLDsa87Pub(pubKey)
	if len(pubKeyBytes) != pubLen {
		return nil, fmt.Errorf("invalid ML-DSA-87 public key length: got %d, want %d", len(pubKeyBytes), pubLen)
	}

	if len(h.kyberCiphertext) != kyberPubLen {
		return nil, fmt.Errorf("invalid KyberCiphertext size: got %d, want %d", len(h.kyberCiphertext), kyberPubLen)
	}

	var msg authRespV4
	copy(msg.RandomPubkey[:], pubKeyBytes)
	copy(msg.KyberCiphertext[:], h.kyberCiphertext)
	copy(msg.Nonce[:], h.respNonce)
	msg.Version = 4
	return &msg, nil
}

func readRawPacket(size int, r io.Reader) ([]byte, error) {
	buf := make([]byte, size)
	n, err := io.ReadFull(r, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:n], nil
}

func (h *encHandshake) handleAuthMsg(msg *authMsgV4, kyberPrv *cryptok.PrivateKey) error {
	rpub, err := cryptod.UnmarshalPubkey(msg.InitiatorPubkey[:]) // Pass slice
	if err != nil {
		return fmt.Errorf("failed to unmarshal initiator public key: %v", err)
	}
	h.remote = rpub
	h.initNonce = msg.Nonce[:]
	// Verify signature
	valid := cryptod.ValidateMLDsa87Signature(rpub, h.initNonce, msg.Signature[:])
	if !valid {
		return fmt.Errorf("ML-DSA-87 signature verification failed")
	}

	// Generate shared secret and ciphertext using NodeB's Kyber public key
	receiverPubKey, err := kyber1024.Scheme().UnmarshalBinaryPublicKey(msg.InitiatorKyberPub[:]) // Pass slice
	if err != nil {
		return fmt.Errorf("failed to unmarshal initiator Kyber public key: %v", err)
	}
	ciphertext, sharedSecret, err := kyber1024.Scheme().Encapsulate(receiverPubKey)
	if err != nil {
		return fmt.Errorf("kyber encapsulation failed: %v", err)
	}
	if len(ciphertext) != kyberPubLen {
		return fmt.Errorf("invalid KyberCiphertext size: got %d, want %d", len(ciphertext), kyberPubLen)
	}
	h.sharedSecret = sharedSecret
	h.kyberCiphertext = ciphertext

	if h.randomPrivKey == nil {
		h.randomPrivKey, err = cryptod.GenerateMLDsa87Key()
		if err != nil {
			return fmt.Errorf("failed to generate random ML-DSA-87 key: %v", err)
		}
	}
	h.remoteRandomPub = rpub
	return nil
}

func (h *encHandshake) secrets(auth, authResp []byte) (Secrets, error) {
	if h.sharedSecret == nil {
		return Secrets{}, errors.New("shared secret not established")
	}
	if len(h.sharedSecret) < 32 {
		return Secrets{}, fmt.Errorf("shared secret too short: got %d bytes, need at least 32", len(h.sharedSecret))
	}

	sharedSecret := h.sharedSecret
	aesKey := sharedSecret[:16] // First 16 bytes for AES-128
	macKey := sharedSecret[16:] // Remaining for MAC (at least 16 bytes)

	s := Secrets{
		AES:            aesKey,
		MAC:            macKey,
		SharedSecret:   sharedSecret,
		remoteKyberPub: h.remoteKyberPub,
		remote:         h.remote,
	}

	// Initialize MACs as HMAC-SHA256 with macKey
	egressMAC := hmac.New(sha256.New, macKey)
	ingressMAC := hmac.New(sha256.New, macKey)

	s.EgressMAC = egressMAC
	s.IngressMAC = ingressMAC
	if s.EgressMAC == nil || s.IngressMAC == nil {
		return Secrets{}, fmt.Errorf("failed to initialize EgressMAC or IngressMAC")
	}
	return s, nil
}

func (h *encHandshake) staticSharedSecret(kyberPrv *cryptok.PrivateKey) ([]byte, []byte, error) {
	if kyberPrv == nil {
		return nil, nil, fmt.Errorf("kyber private key not provided")
	}
	if h.remoteKyberPub == nil {
		return nil, nil, fmt.Errorf("remote Kyber public key not set")
	}
	// skBytes, err := kyberPrv.MarshalBinary()
	// if err != nil {
	// 	fmt.Println("Error marshaling private key:", err)
	// }
	//fmt.Printf("🔹 [staticSharedSecret] Private Key Size: %d, Key: %x\n", len(skBytes), skBytes)

	// pkBytes, err := h.remoteKyberPub.MarshalBinary()
	// if err != nil {
	// 	fmt.Println("Error marshaling public key:", err)
	// }
	//fmt.Printf("🔹 [staticSharedSecret] Public Key Size: %d, Key: %x\n", len(pkBytes))

	sharedSecret, ciphertext, err := cryptok.Encapsulate(h.remoteKyberPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encapsulate shared secret with Kyber-1024: %v", err)
	}
	if len(sharedSecret) != sskLen {
		return nil, nil, fmt.Errorf("unexpected Kyber shared secret length: got %d, want %d", len(sharedSecret), sskLen)
	}
	return sharedSecret, ciphertext, nil
}

// initiatorEncHandshake negotiates a session token on the dialing side.
func initiatorEncHandshake(conn io.ReadWriter, prv *cryptod.PrivateKey, remote *cryptod.PublicKey, kyberPrv *cryptok.PrivateKey, kyberPub *cryptok.PublicKey) (s Secrets, err error) {
	h := &encHandshake{initiator: true, remote: remote}
	authMsg, err := h.makeAuthMsg(prv, kyberPrv)
	if err != nil {
		return s, err
	}

	authPacket, err := sealEIP8(authMsg, h)
	if err != nil {
		return s, err
	}
	if _, err = conn.Write(authPacket); err != nil {
		return s, err
	}
	authRespMsg := new(authRespV4)
	authRespPacket, err := readHandshakeMsg(authRespMsg, encAuthRespLen, prv, kyberPrv, conn)
	if err != nil {
		return s, fmt.Errorf("failed to read response: %v", err)
	}
	if err := h.handleAuthResp(authRespMsg, kyberPrv); err != nil {
		return s, fmt.Errorf("failed to handle response: %v", err)
	}

	s, err = h.secrets(authPacket, authRespPacket)
	if err != nil {
		return s, err
	}
	s.SharedSecret = h.sharedSecret
	return s, nil
}

func (h *encHandshake) makeAuthMsg(prv *cryptod.PrivateKey, kyberPrv *cryptok.PrivateKey) (*authMsgV4, error) {
	h.initNonce = make([]byte, shaLen)
	if _, err := rand.Read(h.initNonce); err != nil {
		return nil, err
	}
	if len(h.initNonce) != shaLen {
		return nil, fmt.Errorf("invalid initNonce size: got %d, want %d", len(h.initNonce), shaLen)
	}

	h.randomPrivKey = prv
	signed := h.initNonce // Sign the nonce directly
	signature, err := cryptod.SignMLDsa87(prv, signed)
	if err != nil {
		return nil, err
	}
	if len(signature) != sigLen {
		return nil, fmt.Errorf("invalid ML-DSA-87 signature length: got %d, want %d", len(signature), sigLen)
	}
	pubKey := prv.Public().(*cryptod.PublicKey)
	pubKeyBytes := cryptod.FromMLDsa87Pub(pubKey)
	if len(pubKeyBytes) != pubLen {
		return nil, fmt.Errorf("invalid ML-DSA-87 public key length: got %d, want %d", len(pubKeyBytes), pubLen)
	}
	kyberPub := kyberPrv.Public().(*cryptok.PublicKey)
	kyberPubBytes, err := kyberPub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Kyber public key: %v", err)
	}
	if len(kyberPubBytes) != kyberPubLen {
		return nil, fmt.Errorf("invalid Kyber-1024 public key length: got %d, want %d", len(kyberPubBytes), kyberPubLen)
	}
	var msg authMsgV4
	copy(msg.Signature[:], signature)
	copy(msg.InitiatorPubkey[:], pubKeyBytes)
	copy(msg.InitiatorKyberPub[:], kyberPubBytes)
	copy(msg.Nonce[:], h.initNonce)
	msg.Version = 4
	return &msg, nil
}

func (h *encHandshake) handleAuthResp(msg *authRespV4, kyberPrv *cryptok.PrivateKey) error {
	h.respNonce = msg.Nonce[:]
	mldsaPubKey, err := cryptod.UnmarshalPubkey(msg.RandomPubkey[:]) // Pass slice
	if err != nil {
		return err
	}
	h.remoteRandomPub = mldsaPubKey
	if len(msg.KyberCiphertext) != kyberPubLen {
		return fmt.Errorf("invalid KyberCiphertext size: got %d, want %d", len(msg.KyberCiphertext), kyberPubLen)
	}

	// Decapsulate shared secret
	sharedSecret, err := cryptok.Decapsulate(kyberPrv, msg.KyberCiphertext[:]) // Pass slice
	if err != nil {
		return fmt.Errorf("kyber decapsulation failed: %v", err)
	}
	h.sharedSecret = sharedSecret // Store for secrets derivation

	return nil
}

func (msg *authMsgV4) decodePlain(input []byte) {
	n := copy(msg.Signature[:], input)
	n += shaLen
	n += copy(msg.InitiatorPubkey[:], input[n:])
	copy(msg.Nonce[:], input[n:])
	msg.Version = 4
	msg.gotPlain = true
}

func (msg *authRespV4) sealPlain(hs *encHandshake) ([]byte, error) {
	buf := make([]byte, authRespLen)
	n := copy(buf, msg.RandomPubkey[:])
	copy(buf[n:], msg.Nonce[:])

	sharedSecret, ciphertext, err := cryptod.EncapsulateMLDsa87(hs.remote)
	if err != nil {
		return nil, err
	}

	encryptedMessage, err := SymmetricEncryptGCM(sharedSecret, buf)
	if err != nil {
		return nil, err
	}

	return append(ciphertext, encryptedMessage...), nil
}

func (msg *authRespV4) decodePlain(input []byte) {
	n := copy(msg.RandomPubkey[:], input)
	copy(msg.Nonce[:], input[n:])
	msg.Version = 4
}

var padSpace = make([]byte, 300)

// Create data with kyber 2024 consistency.

func sealEIP8(msg interface{}, h *encHandshake) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := rlp.Encode(buf, msg); err != nil {
		return nil, err
	}
	plaintext := buf.Bytes()
	prefix := make([]byte, 2)
	binary.BigEndian.PutUint16(prefix, uint16(len(plaintext)))
	finalPacket := append(prefix, plaintext...)
	return finalPacket, nil
}

// SymmetricEncryptGCM performs AES-GCM encryption.
func SymmetricEncryptGCM(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES cipher creation failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM mode creation failed: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %v", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func SymEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext)+aes.BlockSize)
	copy(ciphertext[:aes.BlockSize], iv)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
}

func SymDecrypt(secretKey []byte, ciphertext []byte) ([]byte, error) {
	if len(secretKey) != 16 { // Match AES-128 key size used in Secrets.AES
		return nil, fmt.Errorf("invalid AES key length: %d (must be 16 bytes)", len(secretKey))
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

type plainDecoder interface {
	decodePlain([]byte)
}

func readHandshakeMsg(msg plainDecoder, plainSize int, prv *cryptod.PrivateKey, kyberPrv *cryptok.PrivateKey, r io.Reader) ([]byte, error) {
	prefixBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, prefixBuf); err != nil {
		return nil, fmt.Errorf("failed to read prefix: %v", err)
	}
	length := int(binary.BigEndian.Uint16(prefixBuf))
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("failed to read packet: %v", err)
	}
	receivedData := buf
	if err := rlp.DecodeBytes(receivedData, msg); err != nil {
		return nil, fmt.Errorf("failed to decode RLP message: %v", err)
	}
	return receivedData, nil
}

// SymmetricDecryptGCM performs AES-GCM decryption.
func SymmetricDecryptGCM(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES cipher creation failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM mode creation failed: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short for nonce")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %v", err)
	}
	return plaintext, nil
}

func importPublicKey(pubKey []byte) (*cryptod.PublicKey, error) {
	return cryptod.UnmarshalPubkey(pubKey)
}

func exportPubkey(pub *cryptod.PublicKey) []byte {
	if pub == nil {
		panic("nil pubkey")
	}
	return cryptod.FromMLDsa87Pub(pub)
}

func xor(one, other []byte) []byte {
	if len(one) != len(other) {
		panic(fmt.Sprintf("xor length mismatch: %d vs %d", len(one), len(other)))
	}

	xor := make([]byte, len(one))
	for i := range one {
		xor[i] = one[i] ^ other[i]
	}
	return xor
}

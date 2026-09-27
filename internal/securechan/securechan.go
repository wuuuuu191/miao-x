// Package securechan 实现主控与 agent 之间的加密通道。
// 方案与妙妙屋X 的 mmw-agent securechan 同构：
//   - 身份: 主控持有 Ed25519 长期密钥, agent 预置主控公钥, 握手时主控对临时公钥签名
//   - 密钥: X25519 ECDH → HKDF-SHA256(salt=agentEphPub||masterEphPub, info="securechan-v1")
//     派生双向 AES-256-GCM 密钥与 nonce 基值
//   - 报文: [version(1B)][seq(8B)][GCM密文], 64 位滑动窗口防重放
package securechan

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	EnvelopeVersion = 0x01
	envelopeHeader  = 1 + 8 // version(1) + seq(8)
	gcmTagSize      = 16
	nonceSize       = 12
	windowSize      = 64
	hkdfInfo        = "miaowu-securechan-v1"
)

// Identity 主控长期身份密钥（Ed25519）。
type Identity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// LoadOrGenerate 从 path 加载种子文件，不存在则生成并保存（0600）。
// M8: 文件存在但格式非法时报错退出（人工介入），绝不静默重新生成 ——
// 否则主控公钥一变，所有已部署 agent 会因验签失败集体失联。
func LoadOrGenerate(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) == ed25519.SeedSize {
			priv := ed25519.NewKeyFromSeed(data)
			return &Identity{PrivateKey: priv, PublicKey: priv.Public().(ed25519.PublicKey)}, nil
		}
		return nil, fmt.Errorf("密钥文件 %s 存在但格式非法（%d 字节，期望 %d）——拒绝覆盖，请人工修复或删除该文件后重新初始化",
			path, len(data), ed25519.SeedSize)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("读取密钥文件失败: %w", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv.Seed(), 0600); err != nil {
		return nil, err
	}
	return &Identity{PrivateKey: priv, PublicKey: pub}, nil
}

func (m *Identity) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(m.PublicKey)
}

func ParsePublicKey(b64 string) (ed25519.PublicKey, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(data) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", len(data))
	}
	return ed25519.PublicKey(data), nil
}

// GenerateEphemeral 生成 X25519 临时密钥对。
func GenerateEphemeral() (priv, pub []byte, err error) {
	priv = make([]byte, 32)
	if _, err = rand.Read(priv); err != nil {
		return nil, nil, err
	}
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	return priv, pub, err
}

func ComputeSharedSecret(myPriv, theirPub []byte) ([]byte, error) {
	return curve25519.X25519(myPriv, theirPub)
}

func Sign(priv ed25519.PrivateKey, data []byte) []byte { return ed25519.Sign(priv, data) }

func Verify(pub ed25519.PublicKey, data, sig []byte) bool { return ed25519.Verify(pub, data, sig) }

// Session 持有双向 AES-256-GCM cipher。
type Session struct {
	sendCipher cipher.AEAD
	recvCipher cipher.AEAD
	sendSeq    atomic.Uint64
	sendNonce  [nonceSize]byte
	recvNonce  [nonceSize]byte

	recvMu     sync.Mutex
	recvWindow replayWindow
}

// replayWindow 64 位滑动窗口防重放。
type replayWindow struct {
	maxSeq uint64
	bitmap uint64
}

func (w *replayWindow) Check(seq uint64) bool {
	if seq == 0 {
		return false
	}
	if seq > w.maxSeq {
		shift := seq - w.maxSeq
		if shift >= windowSize {
			w.bitmap = 0
		} else {
			w.bitmap <<= shift
		}
		w.maxSeq = seq
		w.bitmap |= 1
		return true
	}
	diff := w.maxSeq - seq
	if diff >= windowSize {
		return false
	}
	bit := uint64(1) << diff
	if w.bitmap&bit != 0 {
		return false
	}
	w.bitmap |= bit
	return true
}

// DeriveSession 从共享密钥派生双向会话密钥。isMaster 决定方向密钥分配。
func DeriveSession(sharedSecret, agentEphPub, masterEphPub []byte, isMaster bool) (*Session, error) {
	salt := make([]byte, 0, 64)
	salt = append(salt, agentEphPub...)
	salt = append(salt, masterEphPub...)

	hk := hkdf.New(sha256.New, sharedSecret, salt, []byte(hkdfInfo))

	var keys [4][]byte // m2aKey, a2mKey, m2aNonce, a2mNonce
	for i := range keys {
		n := 32
		if i >= 2 {
			n = nonceSize
		}
		keys[i] = make([]byte, n)
		if _, err := io.ReadFull(hk, keys[i]); err != nil {
			return nil, fmt.Errorf("hkdf read: %w", err)
		}
	}

	m2aKey, a2mKey := keys[0], keys[1]
	var sendKey, recvKey []byte
	var sendNonce, recvNonce [nonceSize]byte
	if isMaster {
		sendKey, recvKey = m2aKey, a2mKey
		copy(sendNonce[:], keys[2])
		copy(recvNonce[:], keys[3])
	} else {
		sendKey, recvKey = a2mKey, m2aKey
		copy(sendNonce[:], keys[3])
		copy(recvNonce[:], keys[2])
	}

	sb, _ := aes.NewCipher(sendKey)
	sendCipher, err := cipher.NewGCM(sb)
	if err != nil {
		return nil, err
	}
	rb, _ := aes.NewCipher(recvKey)
	recvCipher, err := cipher.NewGCM(rb)
	if err != nil {
		return nil, err
	}
	return &Session{sendCipher: sendCipher, recvCipher: recvCipher, sendNonce: sendNonce, recvNonce: recvNonce}, nil
}

// Encrypt 输出 [version(1)][seq(8)][ciphertext+tag] 二进制信封。
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	seq := s.sendSeq.Add(1)
	nonce := makeNonce(s.sendNonce, seq)
	ct := s.sendCipher.Seal(nil, nonce[:], plaintext, nil)
	out := make([]byte, envelopeHeader+len(ct))
	out[0] = EnvelopeVersion
	binary.BigEndian.PutUint64(out[1:9], seq)
	copy(out[envelopeHeader:], ct)
	return out, nil
}

// Decrypt 校验并解密信封。
func (s *Session) Decrypt(envelope []byte) ([]byte, error) {
	if len(envelope) < envelopeHeader+gcmTagSize {
		return nil, errors.New("envelope too short")
	}
	if envelope[0] != EnvelopeVersion {
		return nil, fmt.Errorf("unknown envelope version: %d", envelope[0])
	}
	seq := binary.BigEndian.Uint64(envelope[1:9])
	s.recvMu.Lock()
	ok := s.recvWindow.Check(seq)
	s.recvMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("replay or out-of-window seq: %d", seq)
	}
	nonce := makeNonce(s.recvNonce, seq)
	pt, err := s.recvCipher.Open(nil, nonce[:], envelope[envelopeHeader:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return pt, nil
}

func makeNonce(base [nonceSize]byte, seq uint64) [nonceSize]byte {
	var nonce [nonceSize]byte
	copy(nonce[:], base[:])
	var seqBytes [nonceSize]byte
	binary.BigEndian.PutUint64(seqBytes[4:], seq)
	for i := range nonce {
		nonce[i] ^= seqBytes[i]
	}
	return nonce
}

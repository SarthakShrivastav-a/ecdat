// truth: RSA-4096 keygen, ECDSA P-256, SHA-256, AES-GCM, TLS server config
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 4096)
	eck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sum := sha256.Sum256([]byte("gateway"))
	block, _ := aes.NewCipher(sum[:])
	gcm, _ := cipher.NewGCM(block)
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	fmt.Println(key.N.BitLen(), eck.Curve.Params().Name, gcm.NonceSize(), cfg.MinVersion)
}

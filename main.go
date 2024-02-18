// SOURCE: https://gist.github.com/LukaGiorgadze/85b9e09d2008a03adfdfd5eea5964f93
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"reflect"
)

// Elliptic Curve Cryptography (ECC) is a key-based technique for encrypting data.
// ECC focuses on pairs of public and private keys for decryption and encryption of web traffic.
// ECC is frequently discussed in the context of the Rivest–Shamir–Adleman (RSA) cryptographic algorithm.
// EllipticCurve data struct
type EllipticCurve struct {
	pubKeyCurve elliptic.Curve // http://golang.org/pkg/crypto/elliptic/#P256
	privateKey  *ecdsa.PrivateKey
	publicKey   *ecdsa.PublicKey
}

// New EllipticCurve instance
func New(curve elliptic.Curve) *EllipticCurve {
	return &EllipticCurve{
		pubKeyCurve: curve,
		privateKey:  new(ecdsa.PrivateKey),
	}
}

// GenerateKeys EllipticCurve public and private keys
func (ec *EllipticCurve) GenerateKeys() (privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey, err error) {

	privKey, err = ecdsa.GenerateKey(ec.pubKeyCurve, rand.Reader)

	if err == nil {
		ec.privateKey = privKey
		pubKey = &privKey.PublicKey
		ec.publicKey = &privKey.PublicKey
	}

	return
}

// EncodePrivate private key
func (ec *EllipticCurve) EncodePrivate(privKey *ecdsa.PrivateKey) (key string, err error) {

	encoded, err := x509.MarshalECPrivateKey(privKey)

	if err != nil {
		return
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})

	key = string(pemEncoded)

	return
}

// EncodePublic public key
func (ec *EllipticCurve) EncodePublic(pubKey *ecdsa.PublicKey) (key string, err error) {

	encoded, err := x509.MarshalPKIXPublicKey(pubKey)

	if err != nil {
		return
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})

	key = string(pemEncodedPub)
	return
}

// DecodePrivate private key
func (ec *EllipticCurve) DecodePrivate(pemEncodedPriv string) (privateKey *ecdsa.PrivateKey, err error) {
	blockPriv, _ := pem.Decode([]byte(pemEncodedPriv))

	x509EncodedPriv := blockPriv.Bytes

	privateKey, err = x509.ParseECPrivateKey(x509EncodedPriv)

	return
}

// DecodePublic public key
func (ec *EllipticCurve) DecodePublic(pemEncodedPub string) (publicKey *ecdsa.PublicKey, err error) {
	blockPub, _ := pem.Decode([]byte(pemEncodedPub))

	x509EncodedPub := blockPub.Bytes

	genericPublicKey, err := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey = genericPublicKey.(*ecdsa.PublicKey)

	return
}

// VerifySignature sign ecdsa style and verify signature
func (ec *EllipticCurve) VerifySignature(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) (signature []byte, ok bool, err error) {

	h := md5.New()

	_, err = io.WriteString(h, "This is a message to be signed and verified by ECDSA!")
	if err != nil {
		return
	}
	signhash := h.Sum(nil)

	r, s, serr := ecdsa.Sign(rand.Reader, privKey, signhash)
	if serr != nil {
		return []byte(""), false, serr
	}

	signature = r.Bytes()
	signature = append(signature, s.Bytes()...)

	ok = ecdsa.Verify(pubKey, signhash, r, s)

	return
}

// Can be used in _test.go
// Test encode, decode and test it with deep equal
func (ec *EllipticCurve) Test(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) (err error) {

	encPriv, err := ec.EncodePrivate(privKey)
	if err != nil {
		return
	}
	encPub, err := ec.EncodePublic(pubKey)
	if err != nil {
		return
	}
	priv2, err := ec.DecodePrivate(encPriv)
	if err != nil {
		return
	}
	pub2, err := ec.DecodePublic(encPub)
	if err != nil {
		return
	}

	if !reflect.DeepEqual(privKey, priv2) {
		err = errors.New("private keys do not match")
		return
	}
	if !reflect.DeepEqual(pubKey, pub2) {
		err = errors.New("public keys do not match")
		return
	}

	return
}

func main() {
	ec := New(elliptic.P256())
	priv, pub, err := ec.GenerateKeys()
	if err != nil {
		log.Fatal(err, "error generating keys")
	}

	err = ec.Test(priv, pub)
	fmt.Println(err, priv == nil, pub == nil)

	privKey, err := ec.EncodePrivate(priv)
	if err != nil {
		log.Fatal(err, "error encoding private key")
	}

	pubKey, err := ec.EncodePublic(pub)
	if err != nil {
		log.Fatal(err, "error encoding public key")
	}

	fmt.Println("================= PRIVATE KEY ==================")
	fmt.Println(privKey)
	fmt.Println("================================================")

	fmt.Println("================= PUBLIC KEY ==================")
	fmt.Println(pubKey)
	fmt.Println("================================================")
}

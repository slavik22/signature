package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// KeyPair represents a public/private key pair
type KeyPair struct {
	PublicKey  *big.Int // public key
	PrivateKey *big.Int // private key
}

// GenerateKeyPair generates a new public/private key pair
func GenerateKeyPair(p *big.Int, g *big.Int) (*KeyPair, error) {
	// Choose a random private key 'a'
	a, err := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))
	if err != nil {
		return nil, err
	}

	// Compute the public key 'b'
	b := new(big.Int).Exp(g, a, p)

	return &KeyPair{PublicKey: b, PrivateKey: a}, nil
}

// Encrypt encrypts a message using El-Gamal algorithm
func Encrypt(p, g, m, b, k *big.Int) (*big.Int, *big.Int) {
	// Compute x and y
	x := new(big.Int).Exp(g, k, p)
	y1 := new(big.Int).Exp(b, k, p)
	y2 := new(big.Int).Mul(y1, m)
	y := new(big.Int).Mod(y2, p)

	return x, y
}

// Decrypt decrypts a ciphertext using El-Gamal algorithm
func Decrypt(p, a, x, y *big.Int) *big.Int {
	// Compute s
	s := new(big.Int).Exp(x, a, p)

	// Compute the modular inverse of s
	sInverse := new(big.Int).ModInverse(s, p)

	// Compute the decrypted message m
	m1 := new(big.Int).Mul(y, sInverse)
	m := new(big.Int).Mod(m1, p)

	return m
}

func main() {
	p, _ := rand.Prime(rand.Reader, 2048)
	g := new(big.Int).PrimitiveRoot(p)

	keyPair, _ := GenerateKeyPair(p, g)

	m := big.NewInt(123)
	k, _ := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))

	x, y := Encrypt(p, g, m, keyPair.PublicKey, k)

	decryptedMessage := Decrypt(p, keyPair.PrivateKey, x, y)

	fmt.Println("Original Message:", m)
	fmt.Println("Decrypted Message:", decryptedMessage)
}

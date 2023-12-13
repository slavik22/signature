package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// generatePrime generates a random prime number between 2048 and 4096 bits.
func generatePrime() *big.Int {
	min := new(big.Int).SetBit(new(big.Int), 2048, 1)

	p, err := rand.Prime(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	if p.Cmp(min) < 0 {
		return generatePrime()
	}

	return p
}

// generatePrimitiveRoot generates a primitive root modulo p.
func generatePrimitiveRoot(p *big.Int) *big.Int {
	generator := new(big.Int).SetInt64(2) // Start with 2 as a potential primitive root

	a, err := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(1)))

	if err != nil {
		panic("Rand int error")
	}

	for {
		if new(big.Int).Exp(generator, a, p).Cmp(big.NewInt(1)) != 0 {
			return generator
		}
		generator.Add(generator, big.NewInt(1))
	}
}

// generateKeyPair generates a random private key 'a' and corresponding public key 'b'.
func generateKeyPair(p, g *big.Int) (*big.Int, *big.Int) {
	a, err := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(1)))
	if err != nil {
		panic(err)
	}

	b := new(big.Int).Exp(g, a, p)

	return a, b
}

// signMessage generates a digital signature for the given message.
func signMessage(m, a, p, g *big.Int) (*big.Int, *big.Int) {
	// Choose a random number k
	k, err := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(1)))
	if err != nil {
		panic(err)
	}

	// Calculate the first component of the signature: r = g^k mod p
	r := new(big.Int).Exp(g, k, p)

	// Calculate the hash value of the message
	hashed := sha256.Sum256([]byte(m.String()))

	// Calculate the second component of the signature: s = (H(m) - a*r) * k^(-1) mod (p-1)
	hm := new(big.Int).SetBytes(hashed[:])
	ar := new(big.Int).Mul(a, r)
	ar.Mod(ar, new(big.Int).Sub(p, big.NewInt(1)))
	kInverse := new(big.Int).ModInverse(k, new(big.Int).Sub(p, big.NewInt(1)))
	s := new(big.Int).Mul(new(big.Int).Sub(hm, ar), kInverse)
	s.Mod(s, new(big.Int).Sub(p, big.NewInt(1)))

	return r, s
}

// verifySignature verifies the digital signature.
func verifySignature(m, r, s, b, p, g *big.Int) bool {
	// Calculate y = b^(-1) mod p
	y := new(big.Int).ModInverse(b, p)

	// Calculate u1 = (H(m) * s^(-1)) mod (p-1)
	hashed := sha256.Sum256([]byte(m.String()))
	hm := new(big.Int).SetBytes(hashed[:])
	sInverse := new(big.Int).ModInverse(s, new(big.Int).Sub(p, big.NewInt(1)))
	u1 := new(big.Int).Mul(hm, new(big.Int).ModInverse(s, new(big.Int).Sub(p, big.NewInt(1))))
	u1.Mod(u1, new(big.Int).Sub(p, big.NewInt(1)))

	// Calculate u2 = (r * s^(-1)) mod (p-1)
	u2 := new(big.Int).Mul(r, sInverse)
	u2.Mod(u2, new(big.Int).Sub(p, big.NewInt(1)))

	// Calculate v = (g^u1 * y^u2) mod p
	v1 := new(big.Int).Exp(g, u1, p)
	v2 := new(big.Int).Exp(y, u2, p)
	v := new(big.Int).Mul(v1, v2)
	v.Mod(v, p)

	// Check if v equals r
	return v.Cmp(r) == 0
}

func main() {
	p := generatePrime()
	g := generatePrimitiveRoot(p)

	a, b := generateKeyPair(p, g)

	message := "Hello, El-Gamal!"

	m, err := new(big.Int).SetString(message, 10)

	if !err {
		panic("Invalid string format for message")
	}

	r, s := signMessage(m, a, p, g)

	isValid := verifySignature(m, r, s, b, p, g)

	fmt.Printf("Original Message: %s\n", message)
	fmt.Printf("Generated Prime (p): %s\n", p.String())
	fmt.Printf("Primitive Root (g): %s\n", g.String())
	fmt.Printf("Private Key (a): %s\n", a.String())
	fmt.Printf("Public Key (b): %s\n", b.String())
	fmt.Printf("Signature (r, s): (%s, %s)\n", r.String(), s.String())
	fmt.Printf("Is Signature Valid? %t\n", isValid)
}

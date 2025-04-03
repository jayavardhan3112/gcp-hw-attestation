package tpm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// MockTPMSigner provides a mock implementation for testing without a TPM
type MockTPMSigner struct {
	privateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

// NewMockTPMSigner creates a new mock TPM signer
func NewMockTPMSigner() (*MockTPMSigner, error) {
	// Generate a new RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &MockTPMSigner{
		privateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// Sign signs a message using the mock RSA key
func (m *MockTPMSigner) Sign(message []byte) ([]byte, error) {
	// Hash the message
	digest := sha256.Sum256(message)

	// Sign the digest
	signature, err := rsa.SignPKCS1v15(rand.Reader, m.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return nil, fmt.Errorf("mock signing failed: %w", err)
	}

	return signature, nil
}

// SavePublicKey saves the public key to a PEM file
func (m *MockTPMSigner) SavePublicKey(filePath string) error {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(m.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	})

	return ioutil.WriteFile(filePath, pubKeyPEM, 0644)
}

// GetAKCertificate returns an error for the mock
func (m *MockTPMSigner) GetAKCertificate() ([]byte, error) {
	return nil, fmt.Errorf("mock does not support certificates")
}

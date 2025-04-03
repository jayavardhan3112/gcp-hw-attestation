package tpm

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// TPMSigner handles TPM signing operations
type TPMSigner struct {
	Device    string
	rwc       io.ReadWriteCloser
	ak        *client.Key
	PublicKey *rsa.PublicKey
}

// NewTPMSigner creates a new TPM signer
func NewTPMSigner(tpmDevice string) (*TPMSigner, error) {
	if tpmDevice == "" {
		tpmDevice = "/dev/tpmrm0"
	}

	// Open TPM device
	rwc, err := tpm2.OpenTPM(tpmDevice)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM device %s: %w", tpmDevice, err)
	}

	// Get the attestation key
	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		rwc.Close()
		return nil, fmt.Errorf("failed to get attestation key: %w", err)
	}

	// Get the public key
	pubKey, ok := ak.PublicKey().(*rsa.PublicKey)
	if !ok {
		ak.Close()
		rwc.Close()
		return nil, errors.New("attestation key is not an RSA key")
	}

	return &TPMSigner{
		Device:    tpmDevice,
		rwc:       rwc,
		ak:        ak,
		PublicKey: pubKey,
	}, nil
}

// Close releases TPM resources
func (t *TPMSigner) Close() {
	if t.ak != nil {
		t.ak.Close()
	}
	if t.rwc != nil {
		t.rwc.Close()
	}
}

// Sign signs a message using the TPM
func (t *TPMSigner) Sign(message []byte) ([]byte, error) {
	// Hash the message
	digest := sha256.Sum256(message)

	// Create an empty PCR selection since we're not attesting to PCR values
	emptySelection := tpm2.PCRSelection{}

	// QuoteRaw returns the quote information and raw signature
	_, rawSig, err := tpm2.QuoteRaw(
		t.rwc,
		t.ak.Handle(),
		"",        // No password
		"",        // No password
		digest[:], // Use digest as nonce
		emptySelection,
		tpm2.AlgNull, // Use the key's default signing algorithm
	)

	if err != nil {
		return nil, fmt.Errorf("TPM QuoteRaw operation failed: %w", err)
	}

	return rawSig, nil
}

// SavePublicKey saves the public key to a PEM file
func (t *TPMSigner) SavePublicKey(filePath string) error {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(t.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	})

	return ioutil.WriteFile(filePath, pubKeyPEM, 0644)
}

// GetAKCertificate attempts to get the attestation key certificate
// Note: This only works on GCE VMs with vTPM
func (t *TPMSigner) GetAKCertificate() ([]byte, error) {
	// Try different methods to get the certificate
	var cert []byte

	// Method: Try known NV indices for GCP vTPM
	nvIndices := []uint32{0x01c10000, 0x01c00000}
	for _, idx := range nvIndices {
		data, err := tpm2.NVReadEx(t.rwc, tpm2.HandleNull, tpmutil.Handle(idx), "", 0)
		if err == nil && len(data) > 0 {
			// Check if it looks like a certificate (starts with 0x30)
			if len(data) > 1 && data[0] == 0x30 {
				cert = data
				break
			}
		}
	}

	if cert == nil {
		return nil, errors.New("could not retrieve AK certificate, this is expected outside GCE or without vTPM")
	}

	return cert, nil
}

// VerifySignature verifies a signature using a public key
func VerifySignature(message, signature []byte, publicKey *rsa.PublicKey) error {
	digest := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature)
}

// LoadPublicKeyFromFile loads a public key from a PEM file
func LoadPublicKeyFromFile(filePath string) (*rsa.PublicKey, error) {
	pemData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaKey, nil
}

// LoadCertificateFromFile loads a certificate from a PEM file
func LoadCertificateFromFile(filePath string) (*x509.Certificate, error) {
	pemData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

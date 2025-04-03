package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/jayavardhan3112/gcp-hw-attestation/pkg/gce"
	"github.com/jayavardhan3112/gcp-hw-attestation/pkg/tpm"
)

func main() {
	var (
		tpmDevice   = flag.String("tpm", "/dev/tpmrm0", "Path to TPM device")
		message     = flag.String("message", "", "Message to sign")
		messageFile = flag.String("file", "", "File containing message to sign")
		outputDir   = flag.String("output", ".", "Output directory")
		mockMode    = flag.Bool("mock", false, "Use mock TPM signer instead of real TPM")
	)
	flag.Parse()

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Get the message to sign
	var messageData []byte
	var err error

	if *message != "" {
		messageData = []byte(*message)
	} else if *messageFile != "" {
		messageData, err = ioutil.ReadFile(*messageFile)
		if err != nil {
			log.Fatalf("Failed to read message file: %v", err)
		}
	} else {
		// Default message
		messageData = []byte("Hello, TPM World!")
	}

	// Save the message
	messagePath := filepath.Join(*outputDir, "message.txt")
	if err := ioutil.WriteFile(messagePath, messageData, 0644); err != nil {
		log.Fatalf("Failed to save message: %v", err)
	}

	// Check if running on GCE with vTPM
	if gce.IsRunningOnGCE() {
		meta, err := gce.GetInstanceMetadata()
		if err == nil {
			log.Printf("Running on GCE VM: %s", meta.Name)
			log.Printf("Project: %s, Zone: %s", meta.ProjectID, meta.Zone)
			if meta.VTPM {
				log.Printf("VM has vTPM enabled")
			} else {
				log.Printf("Warning: VM does not have vTPM enabled")
			}
		}
	} else {
		log.Printf("Not running on GCE. Some TPM functionality may not be available.")
	}

	// Determine if we should use mock mode
	useMock := *mockMode
	if !useMock {
		// Check if TPM device exists
		if _, err := os.Stat(*tpmDevice); os.IsNotExist(err) {
			log.Printf("TPM device %s not found. Falling back to mock mode.", *tpmDevice)
			useMock = true
		}
	}

	var signature []byte
	var pubKeyPath string = filepath.Join(*outputDir, "public_key.pem")

	if useMock {
		// Use mock signer
		log.Printf("Using mock TPM signer")
		mockSigner, err := tpm.NewMockTPMSigner()
		if err != nil {
			log.Fatalf("Failed to create mock TPM signer: %v", err)
		}

		// Sign the message with mock signer
		signature, err = mockSigner.Sign(messageData)
		if err != nil {
			log.Fatalf("Failed to sign message with mock TPM: %v", err)
		}

		// Save the public key
		if err := mockSigner.SavePublicKey(pubKeyPath); err != nil {
			log.Fatalf("Failed to save mock public key: %v", err)
		}

		// Note: Mock signer won't provide a certificate
		log.Printf("Note: Mock signer doesn't provide attestation certificates")

	} else {
		// Use real TPM signer
		signer, err := tpm.NewTPMSigner(*tpmDevice)
		if err != nil {
			log.Fatalf("Failed to create TPM signer: %v", err)
		}
		defer signer.Close()

		// Sign the message
		signature, err = signer.Sign(messageData)
		if err != nil {
			log.Fatalf("Failed to sign message: %v", err)
		}

		// Save the public key
		if err := signer.SavePublicKey(pubKeyPath); err != nil {
			log.Fatalf("Failed to save public key: %v", err)
		}

		// Try to get and save the certificate (GCE with vTPM only)
		cert, err := signer.GetAKCertificate()
		if err != nil {
			log.Printf("Note: Could not get attestation key certificate: %v", err)
			log.Printf("This is expected outside GCE or without vTPM.")
		} else {
			certPath := filepath.Join(*outputDir, "ak_cert.pem")
			certPEM := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----",
				base64.StdEncoding.EncodeToString(cert))
			if err := ioutil.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
				log.Fatalf("Failed to save certificate: %v", err)
			}
			log.Printf("Attestation key certificate saved to %s", certPath)
		}
	}

	// Save the signature
	signaturePath := filepath.Join(*outputDir, "signature.bin")
	if err := ioutil.WriteFile(signaturePath, signature, 0644); err != nil {
		log.Fatalf("Failed to save signature: %v", err)
	}

	// Save base64 signature for easier transport
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	signatureBase64Path := filepath.Join(*outputDir, "signature.b64")
	if err := ioutil.WriteFile(signatureBase64Path, []byte(signatureBase64), 0644); err != nil {
		log.Fatalf("Failed to save base64 signature: %v", err)
	}

	log.Printf("Signed message saved to %s", messagePath)
	log.Printf("Signature saved to %s", signaturePath)
	log.Printf("Base64 signature saved to %s", signatureBase64Path)
	log.Printf("Public key saved to %s", pubKeyPath)

	if useMock {
		log.Printf("Note: Running in mock mode - signatures will not be TPM-attested")
	}
}

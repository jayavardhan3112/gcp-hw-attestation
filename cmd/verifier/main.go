package main

import (
	"crypto/rsa"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/jayavardhan3112/gcp-hw-attestation/pkg/tpm"
)

func main() {
	var (
		message       = flag.String("message", "", "Message that was signed")
		messageFile   = flag.String("file", "message.txt", "File containing message that was signed")
		signature     = flag.String("signature", "", "Base64 signature")
		signatureFile = flag.String("sig-file", "signature.b64", "File containing base64 signature")
		pubKeyFile    = flag.String("pubkey", "public_key.pem", "Public key file")
		certFile      = flag.String("cert", "", "Certificate file (optional)")
	)
	flag.Parse()

	// Read the message
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
		log.Fatalf("No message provided. Use --message or --file")
	}

	// Read the signature
	var signatureData []byte

	if *signature != "" {
		signatureData, err = base64.StdEncoding.DecodeString(*signature)
		if err != nil {
			log.Fatalf("Failed to decode base64 signature: %v", err)
		}
	} else if *signatureFile != "" {
		signatureBase64, err := ioutil.ReadFile(*signatureFile)
		if err != nil {
			log.Fatalf("Failed to read signature file: %v", err)
		}
		signatureData, err = base64.StdEncoding.DecodeString(string(signatureBase64))
		if err != nil {
			log.Fatalf("Failed to decode base64 signature: %v", err)
		}
	} else {
		log.Fatalf("No signature provided. Use --signature or --sig-file")
	}

	// Load the public key
	pubKey, err := tpm.LoadPublicKeyFromFile(*pubKeyFile)
	if err != nil {
		log.Fatalf("Failed to load public key: %v", err)
	}

	// Verify with public key
	if err := tpm.VerifySignature(messageData, signatureData, pubKey); err != nil {
		log.Fatalf("Signature verification failed: %v", err)
	}

	fmt.Println("✅ Signature verified successfully with public key!")

	// If certificate is provided, verify and display info
	if *certFile != "" {
		cert, err := tpm.LoadCertificateFromFile(*certFile)
		if err != nil {
			log.Printf("Warning: Failed to load certificate: %v", err)
		} else {
			// Verify the signature using the public key from the certificate
			certPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				log.Printf("Warning: Certificate does not contain an RSA public key")
			} else {
				if err := tpm.VerifySignature(messageData, signatureData, certPubKey); err != nil {
					log.Printf("Warning: Signature verification with certificate failed: %v", err)
				} else {
					fmt.Println("✅ Signature verified successfully with certificate!")
				}
			}

			// Display certificate information
			fmt.Println("\nCertificate Information:")
			fmt.Printf("Subject: %s\n", cert.Subject)
			fmt.Printf("Issuer: %s\n", cert.Issuer)
			fmt.Printf("Valid from: %s to %s\n", cert.NotBefore, cert.NotAfter)
		}
	}
}

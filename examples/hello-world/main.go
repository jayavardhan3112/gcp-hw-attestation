package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/jayavardhan3112/gcp-hw-attestation/pkg/gce"
	"github.com/jayavardhan3112/gcp-hw-attestation/pkg/tpm"
)

func main() {
	var (
		sign    = flag.Bool("sign", false, "Sign a message")
		verify  = flag.Bool("verify", false, "Verify a signature")
		message = flag.String("message", "Hello, TPM World!", "Message to sign or verify")
		sigFile = flag.String("signature", "signature.b64", "Signature file path")
		keyFile = flag.String("key", "public_key.pem", "Public key file path")
	)
	flag.Parse()

	if !*sign && !*verify {
		log.Fatalf("Please specify --sign or --verify")
	}

	if *sign {
		// Check if we're on GCE with vTPM
		if gce.IsRunningOnGCE() {
			meta, _ := gce.GetInstanceMetadata()
			fmt.Printf("Running on GCE VM: %s\n", meta.Name)
			if meta.VTPM {
				fmt.Println("VM has vTPM enabled")
			} else {
				fmt.Println("Warning: VM does not have vTPM enabled")
			}
		} else {
			fmt.Println("Not running on GCE")
		}

		// Create a TPM signer
		signer, err := tpm.NewTPMSigner("")
		if err != nil {
			log.Fatalf("Failed to create TPM signer: %v", err)
		}
		defer signer.Close()

		// Sign the message
		signature, err := signer.Sign([]byte(*message))
		if err != nil {
			log.Fatalf("Failed to sign message: %v", err)
		}

		// Save the message
		if err := ioutil.WriteFile("message.txt", []byte(*message), 0644); err != nil {
			log.Fatalf("Failed to save message: %v", err)
		}

		// Save the signature
		signatureBase64 := base64.StdEncoding.EncodeToString(signature)
		if err := ioutil.WriteFile(*sigFile, []byte(signatureBase64), 0644); err != nil {
			log.Fatalf("Failed to save signature: %v", err)
		}

		// Save the public key
		if err := signer.SavePublicKey(*keyFile); err != nil {
			log.Fatalf("Failed to save public key: %v", err)
		}

		fmt.Println("✅ Message signed successfully")
		fmt.Printf("Message: %s\n", *message)
		fmt.Printf("Signature saved to: %s\n", *sigFile)
		fmt.Printf("Public key saved to: %s\n", *keyFile)
	}

	if *verify {
		// Read the message
		messageData := []byte(*message)
		if _, err := os.Stat("message.txt"); err == nil {
			var err error
			messageData, err = ioutil.ReadFile("message.txt")
			if err != nil {
				log.Fatalf("Failed to read message file: %v", err)
			}
			fmt.Printf("Read message from file: %s\n", string(messageData))
		}

		// Read the signature
		signatureBase64, err := ioutil.ReadFile(*sigFile)
		if err != nil {
			log.Fatalf("Failed to read signature file: %v", err)
		}

		signature, err := base64.StdEncoding.DecodeString(string(signatureBase64))
		if err != nil {
			log.Fatalf("Failed to decode base64 signature: %v", err)
		}

		// Load the public key
		pubKey, err := tpm.LoadPublicKeyFromFile(*keyFile)
		if err != nil {
			log.Fatalf("Failed to load public key: %v", err)
		}

		// Verify the signature
		if err := tpm.VerifySignature(messageData, signature, pubKey); err != nil {
			log.Fatalf("Signature verification failed: %v", err)
		}

		fmt.Println("✅ Signature verified successfully")
	}
}

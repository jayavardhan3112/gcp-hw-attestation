#!/bin/bash

# Update system and install dependencies
sudo apt-get update
sudo apt-get install -y make git wget

# Install Go 1.22.1
wget https://go.dev/dl/go1.22.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz

# Set up Go environment
echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc

# Verify Go installation
go version

# Clone the repository
git clone https://github.com/jayavardhan3112/gcp-hw-attestation.git
cd gcp-hw-attestation

# Update go.mod to use Go 1.22
sed -i 's/go 1.21/go 1.22/' go.mod

# Clean and build
make clean
mkdir -p bin
go build -o bin/signer ./cmd/signer
go build -o bin/verifier ./cmd/verifier
go build -o bin/hello-world ./examples/hello-world

# Set permissions
chmod +x bin/*

# Create output directory with proper permissions
sudo mkdir -p output
sudo chmod 755 output
sudo chown $USER:$USER output

# Run signing and verification
echo "Running TPM signing..."
sudo make sign

echo "Running verification..."
make verify

# Check TPM status
echo "Checking TPM status..."
ls -l /dev/tpm*

# Show generated files
echo "Generated files:"
ls -l output/
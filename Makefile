.PHONY: all build clean sign verify

all: build

build:
	@echo "Building TPM attestation tools..."
	@mkdir -p bin
	go build -o bin/signer ./cmd/signer
	go build -o bin/verifier ./cmd/verifier
	go build -o bin/hello-world ./examples/hello-world

sign:
	@echo "Signing message with TPM..."
	@mkdir -p output
	./bin/signer --output=output

verify:
	@echo "Verifying signature..."
	./bin/verifier --file=output/message.txt --sig-file=output/signature.b64 --pubkey=output/public_key.pem

hello-sign:
	@echo "Running Hello World example (signing)..."
	cd examples/hello-world && go run main.go --sign

hello-verify:
	@echo "Running Hello World example (verification)..."
	cd examples/hello-world && go run main.go --verify

clean:
	@echo "Cleaning up..."
	rm -rf bin/* output/*
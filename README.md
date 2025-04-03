# Google Cloud vTPM Attestation

A toolkit for signing data with Google Cloud vTPM and verifying the signatures.

## Overview

This project demonstrates how to use the virtual Trusted Platform Module (vTPM) on Google Cloud VMs for attestation. It allows you to:

1. Sign data using a VM's TPM attestation key
2. Verify signatures to confirm they came from a specific GCP VM
3. Extract identity information from TPM certificates

## Prerequisites

- Go 1.16 or later
- A Google Cloud VM with vTPM enabled
- TPM device access (`/dev/tpmrm0`)

## Quick Start

### Building

```bash
# Build all components
make build
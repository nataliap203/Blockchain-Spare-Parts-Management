#!/bin/bash
set -a
source ../../.env
set +a

echo "Deploying to Sepolia..."
ape run deploy --network ethereum:sepolia:infura
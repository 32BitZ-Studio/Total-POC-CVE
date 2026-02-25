#!/bin/bash
# Test script to verify logrus DoS vulnerability across multiple versions
# Tests: v1.8.1, v1.8.2, v1.8.3, v1.9.0, v1.9.1, v1.9.2, v1.9.3

versions=("v1.8.1" "v1.8.2" "v1.8.3" "v1.9.0" "v1.9.1" "v1.9.2" "v1.9.3")

echo "========================================"
echo "logrus DoS Vulnerability Version Test"
echo "========================================"
echo ""

for version in "${versions[@]}"; do
    echo "Testing version: $version"
    echo "----------------------------------------"
    
    # Clean up previous version
    rm -f go.mod go.sum
    
    # Initialize and get specific version
    go mod init poclogrus > /dev/null 2>&1
    go get "github.com/sirupsen/logrus@$version" > /dev/null 2>&1
    
    # Run PoC and capture output
    output=$(go run ./poc_logrus_dos_improved.go 2>&1)
    
    # Check if vulnerable
    # The error message appears in all versions, but the key is whether Writer becomes unusable
    hasError=$(echo "$output" | grep -q "bufio.Scanner: token too long" && echo "true" || echo "false")
    writerBroken=$(echo "$output" | grep -q "Writer is broken\|Writer() is no longer functional\|io: read/write on closed pipe" && echo "true" || echo "false")
    writerWorks=$(echo "$output" | grep -q "Second write succeeded\|Writer() is still functional" && echo "true" || echo "false")
    
    # Vulnerable if Writer is broken (even if error appears)
    # Fixed if Writer continues to work (even if error is logged)
    if [ "$writerBroken" = "true" ]; then
        status="VULNERABLE"
        color="\033[0;31m"  # Red
    elif [ "$writerWorks" = "true" ]; then
        status="FIXED"
        color="\033[0;32m"  # Green
    else
        # Fallback: if error appears but we can't determine Writer status
        if [ "$hasError" = "true" ]; then
            status="UNCLEAR"
            color="\033[0;33m"  # Yellow
        else
            status="FIXED"
            color="\033[0;32m"  # Green
        fi
    fi
    
    echo -e "Status: ${color}${status}\033[0m"
    echo ""
    
    # Clean up for next iteration
    sleep 1
done

echo "========================================"
echo "Test Summary"
echo "========================================"
echo ""


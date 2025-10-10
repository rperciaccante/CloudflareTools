#!/bin/bash

# ==============================================================================
# SYNOPSIS
#     Performs TCP and UDP connection tests against a list of hosts and ports.
#
# DESCRIPTION
#     This script iterates through a defined list of hostnames, ports, protocols,
#     and descriptions, using the 'nc' (netcat) command to check for successful
#     connections. It provides a colored output to clearly indicate which tests
#     passed and which failed, along with a custom description.
#
# NOTES
#  Original Author: 
#  Gemini
#   
#   Maintaining Author:
#   Bob Perciaccante
#
#   Version: 1.3 - October 10, 2025
#   - Added tests for QUIC protocol (UDP/7844)
#   - Added test for DNS (UDP/53) to Cloudflare 1.1.1.1/1.0.0.1
#
# EXAMPLE
#     ./test_connections.sh
#     This will run the script and display the test results to the console.
#
# LINK
#     https://linux.die.net/man/1/nc
# ==============================================================================

# Define ANSI color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Define the list of hosts, ports, protocols, and descriptions to test.
# Each entry is a string with values separated by commas.
# The Protocol should be either "TCP" or "UDP".
tests=(
    # Cloudflare Global Region 1
    "region1.v2.argotunnel.com,7844,TCP,Cloudflared Global Region 1 (http2)"
    "region1.v2.argotunnel.com,7844,UDP,Cloudflared Global Region 1 (quic)"

    # Cloudflare Global Region 2
    "region2.v2.argotunnel.com,7844,TCP,Cloudflared Global Region 2 (http2)"
    "region2.v2.argotunnel.com,7844,UDP,Cloudflared Global Region 2 (quic)"

    # Cloudflare US Region 1
    "us-region1.v2.argotunnel.com,7844,TCP,Cloudflared US Region 1 (http2)"
    "us-region1.v2.argotunnel.com,7844,UDP,Cloudflared US Region 1 (quic)"

    # Cloudflare US Region 2
    "us-region2.v2.argotunnel.com,7844,TCP,Cloudflared US Region 2 (http2)"
    "us-region2.v2.argotunnel.com,7844,UDP,Cloudflared US Region 2 (quic)"

    # Cloudflare software update check
    "api.cloudflare.com,443,TCP,Cloudflared Update Server (HTTPS)"
    "update.argotunnel.com,443,TCP,Cloudflared Update Server (HTTPS)"

    # DNS Check to Cloudflare
    "1.1.1.1,53,UDP,Cloudflare DNS Query (UDP)"
    "1.0.0.1,53,UDP,Cloudflare DNS Query (UDP)"
)

echo -e "${YELLOW}Starting TCP/UDP connection tests...${NC}"

# Iterate through each test case
for test_case in "${tests[@]}"; do
    # Parse the values from the string
    hostname=$(echo "$test_case" | cut -d',' -f1)
    port=$(echo "$test_case" | cut -d',' -f2)
    protocol=$(echo "$test_case" | cut -d',' -f3)
    description=$(echo "$test_case" | cut -d',' -f4)

    echo -n "Testing connection to $hostname on port $port ($protocol) - $description..."

    is_successful=false

    # Check the protocol and run the appropriate test
    if [ "$protocol" == "UDP" ]; then
        # Use nc for UDP test.
        # The -u flag specifies UDP.
        # The -z flag is used for zero-I/O mode.
        # -w 3 sets a 3-second timeout.
        # &>/dev/null redirects stdout and stderr to suppress output.
        nc -uz -w 3 "$hostname" "$port" &>/dev/null
        if [ $? -eq 0 ]; then
            is_successful=true
        fi
    elif [ "$protocol" == "TCP" ]; then
        # Use nc for TCP test.
        nc -z -w 3 "$hostname" "$port" &>/dev/null
        if [ $? -eq 0 ]; then
            is_successful=true
        fi
    else
        echo -e " ${RED}Unknown protocol '$protocol'. Skipping.${NC}"
        continue
    fi

    # Output the result based on the boolean flag
    if [ "$is_successful" == true ]; then
        echo -e "${GREEN}PASSED${NC}"
    else
        echo -e "${RED}FAILED${NC}"
    fi
done

echo -e "\n${YELLOW}All tests complete.${NC}"

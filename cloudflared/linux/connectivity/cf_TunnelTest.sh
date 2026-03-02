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
#  *** This is not an official Cloudflare troubleshooting script. It is a
#  *** custom script created by a Cloufdlare engineer to help with troubleshooting
#  *** Cloudflare Tunnel connectivity issues. Tests are based on the official
#  *** Cloudflare connectivity pre-checks documentation located at 
#  *** https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/troubleshoot-tunnels/connectivity-prechecks/#3-test-network-connectivity 
#  *** and updated as of the latest release below.
#
#   Version: 1.4 - March 2, 2026
#   - Updated nc flags to match Cloudflare connectivity pre-checks documentation
#     (nc -uvz for UDP, nc -vz for TCP)
#   - Added DNS resolution tests using dig (doc step 2) before connectivity tests
#   - Resolved hostnames to IPs before testing connectivity (doc step 3)
#
#   Version: 1.3 - October 10, 2025
#   - Added tests for QUIC protocol (UDP/7844)
#   - Added test for DNS (UDP/53) to Cloudflare 1.1.1.1/1.0.0.1
#
# EXAMPLE
#     ./cf_TunnelTest.sh
#     This will run the script and display the test results to the console.
#
#     ./cf_TunnelTest.sh -o results.txt
#     Save the output to results.txt (colors stripped).
#
#     ./cf_TunnelTest.sh -v
#     Run with verbose output showing exact commands and full results.
#
#     ./cf_TunnelTest.sh -v -o results.txt
#     Verbose output saved to file for use in a support ticket.
#
# LINK
#     https://linux.die.net/man/1/nc
#     https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/troubleshoot-tunnels/connectivity-prechecks/
# ==============================================================================

# Define ANSI color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color
CYAN='\033[0;36m'

# Script metadata
SCRIPT_NAME="cf_TunnelTest.sh"
SCRIPT_VERSION="1.4"

# Help function
show_help() {
    cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} - Cloudflare Tunnel Connectivity Pre-Check

SYNOPSIS
    Validates DNS resolution and network connectivity to Cloudflare Tunnel
    endpoints before deploying cloudflared. Tests are based on the official
    Cloudflare connectivity pre-checks documentation.

USAGE
    ./${SCRIPT_NAME} [OPTIONS]

OPTIONS
    -h, --help          Show this help message and exit.
    -v                  Verbose mode. Display the exact command run and
                        full output for each test. Useful for diagnostics.
    -o <file>           Save output to <file> with ANSI colors stripped.
                        Terminal output is unaffected.
    -s                  Silent mode. Suppress all console output and write
                        only to the file specified by -o. Requires -o.

EXAMPLES
    ./${SCRIPT_NAME}
        Run all tests and display results to the console.

    ./${SCRIPT_NAME} -v
        Run all tests with verbose output showing each command and its
        full result.

    ./${SCRIPT_NAME} -o results.txt
        Run all tests and save a plain-text copy to results.txt.

    ./${SCRIPT_NAME} -v -o results.txt
        Verbose output to the terminal and a plain-text file, suitable
        for attaching to a Cloudflare support ticket.

    ./${SCRIPT_NAME} -s -o results.txt
        Run silently with no console output; results saved to file only.

    ./${SCRIPT_NAME} -v -s -o results.txt
        Verbose results written to file only, nothing on the console.

TESTS PERFORMED
    Step 2  - DNS resolution (dig A/AAAA) for tunnel region endpoints,
              with a comparison against the 1.1.1.1 resolver.
    Step 3  - TCP and UDP connectivity (nc) to Cloudflare tunnel endpoints
              on port 7844, plus HTTPS (443) update servers and DNS (53).

REFERENCES
    https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/troubleshoot-tunnels/connectivity-prechecks/
EOF
    exit 0
}

# Handle --help before getopts (getopts does not support long options)
for arg in "$@"; do
    if [ "$arg" == "--help" ]; then
        show_help
    fi
done

# Parse command-line options
OUTPUT_FILE=""
VERBOSE=false
SILENT=false
while getopts ":hsvo:" opt; do
    case $opt in
        h)
            show_help
            ;;
        s)
            SILENT=true
            ;;
        v)
            VERBOSE=true
            ;;
        o)
            OUTPUT_FILE="$OPTARG"
            ;;
        \?)
            echo "Usage: $0 [-h] [-v] [-s] [-o output_file]"
            exit 1
            ;;
    esac
done

# Silent mode requires -o
if [ "$SILENT" == true ] && [ -z "$OUTPUT_FILE" ]; then
    echo "Error: -s (silent) requires -o <file>."
    echo "Usage: $0 [-h] [-v] [-s] [-o output_file]"
    exit 1
fi

# Set up output redirection
if [ "$SILENT" == true ]; then
    exec > >(sed 's/\x1b\[[0-9;]*m//g' > "$OUTPUT_FILE")
    exec 2>&1
elif [ -n "$OUTPUT_FILE" ]; then
    exec > >(tee >(sed 's/\x1b\[[0-9;]*m//g' > "$OUTPUT_FILE"))
    exec 2>&1
fi

# Print script info banner
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}Cloudflare Tunnel Connectivity Pre-Check v${SCRIPT_VERSION}"
echo -e "${CYAN}Script:    ${NC}${SCRIPT_NAME} v${SCRIPT_VERSION}"
echo -e "${CYAN}Hostname:  ${NC}$(hostname)"
echo -e "${CYAN}Run Time:  ${NC}$(date '+%Y-%m-%d %H:%M:%S %Z')"
echo -e "${CYAN}Run As:    ${NC}$(whoami)"
echo -e "${CYAN}Run From:  ${NC}$(pwd)"
echo -e "${CYAN}============================================================${NC}"
echo ""

# Define the list of hosts, ports, protocols, and descriptions to test.
# Each entry is a string with values separated by commas.
# The Protocol should be either "TCP" or "UDP".
tests=(
    # Cloudflare Global Region 1
    "region1.v2.argotunnel.com,7844,TCP,Cloudflare Global Region 1 (http2)"
    "region1.v2.argotunnel.com,7844,UDP,Cloudflare Global Region 1 (quic)"

    # Cloudflare Global Region 2
    "region2.v2.argotunnel.com,7844,TCP,Cloudflare Global Region 2 (http2)"
    "region2.v2.argotunnel.com,7844,UDP,Cloudflare Global Region 2 (quic)"

    # Cloudflare US Region 1
    "us-region1.v2.argotunnel.com,7844,TCP,Cloudflare US Region 1 (http2)"
    "us-region1.v2.argotunnel.com,7844,UDP,Cloudflare US Region 1 (quic)"

    # Cloudflare US Region 2
    "us-region2.v2.argotunnel.com,7844,TCP,Cloudflare US Region 2 (http2)"
    "us-region2.v2.argotunnel.com,7844,UDP,Cloudflare US Region 2 (quic)"

    # Cloudflare software update check
    "api.cloudflare.com,443,TCP,Cloudflared Update Server (HTTPS)"
    "update.argotunnel.com,443,TCP,Cloudflared Update Server (HTTPS)"

    # DNS Check to Cloudflare
    "1.1.1.1,53,UDP,Cloudflare DNS Query (UDP)"
    "1.0.0.1,53,UDP,Cloudflare DNS Query (UDP)"
)

# ==============================================================================
# Step 2: DNS Resolution Tests (dig)
# Ref: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/troubleshoot-tunnels/connectivity-prechecks/#2-dns-test-with-dig
# ==============================================================================

# List of tunnel endpoint hostnames to resolve
dns_hosts=(
    "region1.v2.argotunnel.com"
    "region2.v2.argotunnel.com"
    "us-region1.v2.argotunnel.com"
    "us-region2.v2.argotunnel.com"
)

echo -e "${YELLOW}Step 2: Running DNS resolution tests with dig...${NC}"
for dns_host in "${dns_hosts[@]}"; do
    cmd="dig +short A $dns_host"
    if [ "$VERBOSE" == true ]; then
        echo -e "  ${CYAN}> $cmd${NC}"
    fi
    dig_output=$(dig +short A "$dns_host" 2>/dev/null)
    if [ -n "$dig_output" ]; then
        first_ip=$(echo "$dig_output" | head -n1)
        echo -e "  dig A $dns_host ... ${GREEN}OK${NC} (e.g. $first_ip)"
        if [ "$VERBOSE" == true ]; then
            echo "$dig_output" | while IFS= read -r line; do echo "    $line"; done
        fi
    else
        echo -e "  dig A $dns_host ... ${RED}FAILED (no A records returned)${NC}"
    fi

    cmd="dig +short AAAA $dns_host"
    if [ "$VERBOSE" == true ]; then
        echo -e "  ${CYAN}> $cmd${NC}"
    fi
    dig_output=$(dig +short AAAA "$dns_host" 2>/dev/null)
    if [ -n "$dig_output" ]; then
        first_ip=$(echo "$dig_output" | head -n1)
        echo -e "  dig AAAA $dns_host ... ${GREEN}OK${NC} (e.g. $first_ip)"
        if [ "$VERBOSE" == true ]; then
            echo "$dig_output" | while IFS= read -r line; do echo "    $line"; done
        fi
    else
        echo -e "  dig AAAA $dns_host ... ${RED}FAILED (no AAAA records returned)${NC}"
    fi
done

# Compare against 1.1.1.1 resolver
echo -e "\n${YELLOW}Step 2.2: Comparing DNS against 1.1.1.1 resolver...${NC}"
for dns_host in "${dns_hosts[@]}"; do
    cmd="dig +short A $dns_host @1.1.1.1"
    if [ "$VERBOSE" == true ]; then
        echo -e "  ${CYAN}> $cmd${NC}"
    fi
    dig_output=$(dig +short A "$dns_host" @1.1.1.1 2>/dev/null)
    if [ -n "$dig_output" ]; then
        first_ip=$(echo "$dig_output" | head -n1)
        echo -e "  dig A $dns_host @1.1.1.1 ... ${GREEN}OK${NC} (e.g. $first_ip)"
        if [ "$VERBOSE" == true ]; then
            echo "$dig_output" | while IFS= read -r line; do echo "    $line"; done
        fi
    else
        echo -e "  dig A $dns_host @1.1.1.1 ... ${RED}FAILED (no A records returned)${NC}"
    fi
done

# ==============================================================================
# Step 3: Network Connectivity Tests (nc)
# Ref: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/troubleshoot-tunnels/connectivity-prechecks/#3-test-network-connectivity
# ==============================================================================

echo -e "\n${YELLOW}Step 3: Starting TCP/UDP connection tests...${NC}"

# Iterate through each test case
for test_case in "${tests[@]}"; do
    # Parse the values from the string
    hostname=$(echo "$test_case" | cut -d',' -f1)
    port=$(echo "$test_case" | cut -d',' -f2)
    protocol=$(echo "$test_case" | cut -d',' -f3)
    description=$(echo "$test_case" | cut -d',' -f4)

    echo -n "Testing connection to $hostname on port $port ($protocol) - $description..."

    is_successful=false
    nc_cmd=""
    nc_output=""

    # Check the protocol and run the appropriate test
    if [ "$protocol" == "UDP" ]; then
        # Use nc for UDP test.
        # The -u flag specifies UDP.
        # The -v flag enables verbose output.
        # The -z flag is used for zero-I/O mode.
        # -w 3 sets a 3-second timeout.
        # Ref: nc -uvz -w 3 <IP> <PORT>
        nc_cmd="nc -uvz -w 3 $hostname $port"
        nc_output=$(nc -uvz -w 3 "$hostname" "$port" 2>&1)
        if [ $? -eq 0 ]; then
            is_successful=true
        fi
    elif [ "$protocol" == "TCP" ]; then
        # Use nc for TCP test.
        # Ref: nc -vz -w 3 <IP> <PORT>
        nc_cmd="nc -vz -w 3 $hostname $port"
        nc_output=$(nc -vz -w 3 "$hostname" "$port" 2>&1)
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

    # In verbose mode, show the exact command and its output
    if [ "$VERBOSE" == true ]; then
        echo -e "    ${CYAN}> $nc_cmd${NC}"
        if [ -n "$nc_output" ]; then
            echo "$nc_output" | while IFS= read -r line; do echo "      $line"; done
        fi
    fi
done

echo -e "\n${YELLOW}All tests complete.${NC}"

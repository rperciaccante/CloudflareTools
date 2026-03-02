#!/bin/bash

# ==============================================================================
# SYNOPSIS
#     Auto-generates a Cloudflare Tunnel connectivity test script by fetching
#     the latest endpoint data directly from the official Cloudflare documentation.
#
# DESCRIPTION
#     This script pulls the raw MDX source for the "Tunnel with firewall" page
#     from the cloudflare-docs GitHub repository, parses out all tunnel endpoint
#     hostnames, IP addresses, ports, and protocols, then generates a complete
#     runnable bash test script that validates DNS and network connectivity.
#
#     The generated script follows the official Cloudflare connectivity
#     pre-checks guide:
#     https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/troubleshoot-tunnels/connectivity-prechecks/
#
# NOTES
#  Maintaining Author:
#  Bob Perciaccante
#
#   Version: 1.0 - March 2, 2026
#   - Initial release: auto-generates test script from live Cloudflare docs
#
# USAGE
#     ./cf_GenerateTunnelTest.sh
#         Generates cf_TunnelTest_generated.sh in the current directory.
#
#     ./cf_GenerateTunnelTest.sh -o /path/to/output_script.sh
#         Generates the test script at the specified path.
#
# LINK
#     https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-with-firewall/
#     https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/troubleshoot-tunnels/connectivity-prechecks/
# ==============================================================================

set -euo pipefail

# --- Configuration ---
FIREWALL_DOC_URL="https://raw.githubusercontent.com/cloudflare/cloudflare-docs/production/src/content/docs/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-with-firewall.mdx"
GENERATOR_VERSION="1.0"
OUTPUT_FILE="cf_TunnelTest_generated.sh"

# --- Color codes ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Parse arguments ---
show_help() {
    cat <<EOF
cf_GenerateTunnelTest.sh v${GENERATOR_VERSION}

Fetches the latest Cloudflare Tunnel firewall documentation from GitHub and
generates a connectivity test script based on the current endpoint data.

USAGE
    ./cf_GenerateTunnelTest.sh [OPTIONS]

OPTIONS
    -h, --help      Show this help message and exit.
    -o <file>       Output file path for the generated script.
                    Default: ./cf_TunnelTest_generated.sh

EXAMPLES
    ./cf_GenerateTunnelTest.sh
    ./cf_GenerateTunnelTest.sh -o /tmp/tunnel_test.sh

REQUIREMENTS
    curl, grep, sed, awk
EOF
    exit 0
}

for arg in "$@"; do
    [ "$arg" == "--help" ] && show_help
done

while getopts ":ho:" opt; do
    case $opt in
        h) show_help ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        \?) echo "Usage: $0 [-h] [-o output_file]"; exit 1 ;;
    esac
done

# --- Step 1: Fetch the raw MDX ---
echo -e "${CYAN}[1/4]${NC} Fetching Cloudflare Tunnel firewall documentation..."
MDX_CONTENT=$(curl -sS --fail "$FIREWALL_DOC_URL" 2>/dev/null)
if [ -z "$MDX_CONTENT" ]; then
    echo -e "${RED}ERROR: Failed to fetch documentation from GitHub.${NC}"
    echo "  URL: $FIREWALL_DOC_URL"
    echo "  Check your internet connection and try again."
    exit 1
fi
echo -e "  ${GREEN}OK${NC} - Fetched $(echo "$MDX_CONTENT" | wc -l | tr -d ' ') lines"

# --- Step 2: Parse tunnel endpoints ---
echo -e "${CYAN}[2/4]${NC} Parsing tunnel endpoints from documentation..."

# Temporary files for parsed data
TMPDIR=$(mktemp -d)
TUNNEL_ENDPOINTS_FILE="$TMPDIR/tunnel_endpoints.txt"
DNS_HOSTS_FILE="$TMPDIR/dns_hosts.txt"
OPTIONAL_ENDPOINTS_FILE="$TMPDIR/optional_endpoints.txt"

# Parse the MDX to extract endpoint blocks
# Format: hostname|port|protocols|section
# We look for #### `hostname` patterns followed by table rows

parse_endpoints() {
    local mdx="$1"
    local current_host=""
    local current_section="required"
    local in_optional=false

    while IFS= read -r line; do
        # Detect section changes
        if echo "$line" | grep -q "^### Optional"; then
            in_optional=true
            current_section="optional"
        fi
        if echo "$line" | grep -q "^### Required"; then
            in_optional=false
            current_section="required"
        fi
        if echo "$line" | grep -q "^### Region US"; then
            in_optional=false
            current_section="us-region"
        fi

        # Detect hostname headers: #### `hostname`
        if echo "$line" | grep -qE '^\#{4} `[a-zA-Z0-9._-]+`'; then
            current_host=$(echo "$line" | sed -E 's/^#{4} `([^`]+)`.*/\1/')
        fi

        # Detect table data rows with port numbers
        if [ -n "$current_host" ] && echo "$line" | grep -qE '^\|.*\|.*\| [0-9]+ +\|'; then
            local port=$(echo "$line" | awk -F'|' '{print $4}' | tr -d ' ')
            local protocols=$(echo "$line" | awk -F'|' '{print $5}' | tr -d ' ')

            # Extract IPv4 addresses
            local ipv4s=$(echo "$line" | awk -F'|' '{print $2}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)

            if [ "$current_section" == "optional" ]; then
                echo "${current_host}|${port}|${protocols}|${current_section}|${ipv4s}" >> "$OPTIONAL_ENDPOINTS_FILE"
            else
                echo "${current_host}|${port}|${protocols}|${current_section}|${ipv4s}" >> "$TUNNEL_ENDPOINTS_FILE"

                # Only add resolvable hostnames (not IPs, not SNI-only) to DNS hosts
                if echo "$current_host" | grep -qE 'argotunnel\.com$' && \
                   ! echo "$current_host" | grep -q '^_'; then
                    echo "$current_host" >> "$DNS_HOSTS_FILE"
                fi
            fi
        fi
    done <<< "$mdx"

    # Deduplicate DNS hosts
    if [ -f "$DNS_HOSTS_FILE" ]; then
        sort -u "$DNS_HOSTS_FILE" -o "$DNS_HOSTS_FILE"
    fi
}

parse_endpoints "$MDX_CONTENT"

# Count what we found
TUNNEL_COUNT=0
OPTIONAL_COUNT=0
DNS_COUNT=0
[ -f "$TUNNEL_ENDPOINTS_FILE" ] && TUNNEL_COUNT=$(wc -l < "$TUNNEL_ENDPOINTS_FILE" | tr -d ' ')
[ -f "$OPTIONAL_ENDPOINTS_FILE" ] && OPTIONAL_COUNT=$(wc -l < "$OPTIONAL_ENDPOINTS_FILE" | tr -d ' ')
[ -f "$DNS_HOSTS_FILE" ] && DNS_COUNT=$(wc -l < "$DNS_HOSTS_FILE" | tr -d ' ')

echo -e "  ${GREEN}OK${NC} - Found ${TUNNEL_COUNT} required endpoint entries, ${OPTIONAL_COUNT} optional, ${DNS_COUNT} DNS hosts"

if [ "$TUNNEL_COUNT" -eq 0 ]; then
    echo -e "${RED}ERROR: No tunnel endpoints found. The doc format may have changed.${NC}"
    echo "  Check: $FIREWALL_DOC_URL"
    rm -rf "$TMPDIR"
    exit 1
fi

# --- Step 3: Generate the test script ---
echo -e "${CYAN}[3/4]${NC} Generating test script: ${OUTPUT_FILE}..."

GENERATED_DATE=$(date '+%Y-%m-%d %H:%M:%S %Z')

cat > "$OUTPUT_FILE" << 'SCRIPT_HEADER'
#!/bin/bash

# ==============================================================================
# AUTO-GENERATED Cloudflare Tunnel Connectivity Test Script
#
# This script was auto-generated by cf_GenerateTunnelTest.sh by fetching the
# latest endpoint data from the official Cloudflare documentation at:
#   https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-with-firewall/
#
# Tests follow the official Cloudflare connectivity pre-checks guide:
#   https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/troubleshoot-tunnels/connectivity-prechecks/
#
SCRIPT_HEADER

# Inject the generation timestamp
cat >> "$OUTPUT_FILE" << SCRIPT_META
# Generated: ${GENERATED_DATE}
# Generator: cf_GenerateTunnelTest.sh v${GENERATOR_VERSION}
# Source:    ${FIREWALL_DOC_URL}
#
# USAGE
#     ./$(basename "$OUTPUT_FILE")
#     ./$(basename "$OUTPUT_FILE") -v
#     ./$(basename "$OUTPUT_FILE") -v -o results.txt
#     ./$(basename "$OUTPUT_FILE") -s -o results.txt
#     ./$(basename "$OUTPUT_FILE") -h
# ==============================================================================

SCRIPT_META

cat >> "$OUTPUT_FILE" << 'SCRIPT_BODY_1'
# Define ANSI color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color
CYAN='\033[0;36m'

SCRIPT_BODY_1

# Inject script metadata
cat >> "$OUTPUT_FILE" << SCRIPT_META2
SCRIPT_NAME="$(basename "$OUTPUT_FILE")"
SCRIPT_GENERATED="${GENERATED_DATE}"
SCRIPT_META2

cat >> "$OUTPUT_FILE" << 'SCRIPT_BODY_2'

# Help function
show_help() {
    cat <<EOF
${SCRIPT_NAME} - Auto-Generated Cloudflare Tunnel Connectivity Pre-Check

SYNOPSIS
    Validates DNS resolution and network connectivity to Cloudflare Tunnel
    endpoints. Auto-generated from the official Cloudflare documentation.

USAGE
    ./${SCRIPT_NAME} [OPTIONS]

OPTIONS
    -h, --help          Show this help message and exit.
    -v                  Verbose mode. Display the exact command run and
                        full output for each test.
    -o <file>           Save output to <file> with ANSI colors stripped.
    -s                  Silent mode. No console output, write only to file.
                        Requires -o.

EXAMPLES
    ./${SCRIPT_NAME}
    ./${SCRIPT_NAME} -v
    ./${SCRIPT_NAME} -v -o results.txt
    ./${SCRIPT_NAME} -s -o results.txt
EOF
    exit 0
}

# Handle --help
for arg in "$@"; do
    [ "$arg" == "--help" ] && show_help
done

# Parse options
OUTPUT_FILE=""
VERBOSE=false
SILENT=false
while getopts ":hsvo:" opt; do
    case $opt in
        h) show_help ;;
        s) SILENT=true ;;
        v) VERBOSE=true ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        \?) echo "Usage: $0 [-h] [-v] [-s] [-o output_file]"; exit 1 ;;
    esac
done

# Silent requires -o
if [ "$SILENT" == true ] && [ -z "$OUTPUT_FILE" ]; then
    echo "Error: -s (silent) requires -o <file>."
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

# Banner
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}Cloudflare Tunnel Connectivity Pre-Check (Auto-Generated)${NC}"
echo -e "${CYAN}Script:    ${NC}${SCRIPT_NAME}"
echo -e "${CYAN}Generated: ${NC}${SCRIPT_GENERATED}"
echo -e "${CYAN}Hostname:  ${NC}$(hostname)"
echo -e "${CYAN}Run Time:  ${NC}$(date '+%Y-%m-%d %H:%M:%S %Z')"
echo -e "${CYAN}Run As:    ${NC}$(whoami)"
echo -e "${CYAN}Run From:  ${NC}$(pwd)"
echo -e "${CYAN}============================================================${NC}"
echo ""

# ==============================================================================
# Step 2: DNS Resolution Tests
# ==============================================================================

SCRIPT_BODY_2

# Inject the DNS hosts list
echo 'dns_hosts=(' >> "$OUTPUT_FILE"
if [ -f "$DNS_HOSTS_FILE" ]; then
    while IFS= read -r host; do
        echo "    \"$host\"" >> "$OUTPUT_FILE"
    done < "$DNS_HOSTS_FILE"
fi
echo ')' >> "$OUTPUT_FILE"
echo '' >> "$OUTPUT_FILE"

cat >> "$OUTPUT_FILE" << 'SCRIPT_DNS'
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
# Step 3: Network Connectivity Tests
# ==============================================================================

SCRIPT_DNS

# Build the tests array from parsed endpoints
echo 'echo -e "\n${YELLOW}Step 3: Starting TCP/UDP connection tests...${NC}"' >> "$OUTPUT_FILE"
echo '' >> "$OUTPUT_FILE"
echo 'tests=(' >> "$OUTPUT_FILE"

# Required tunnel endpoints (port 7844 TCP/UDP)
if [ -f "$TUNNEL_ENDPOINTS_FILE" ]; then
    while IFS='|' read -r host port protocols section ipv4s; do
        # Determine label based on section
        case "$section" in
            required)  label="Cloudflare Global" ;;
            us-region) label="Cloudflare US Region" ;;
            *)         label="Cloudflare" ;;
        esac

        # Generate TCP and UDP entries based on protocols
        if echo "$protocols" | grep -qi "tcp"; then
            echo "    \"${host},${port},TCP,${label} - ${host} (http2)\"" >> "$OUTPUT_FILE"
        fi
        if echo "$protocols" | grep -qi "udp"; then
            echo "    \"${host},${port},UDP,${label} - ${host} (quic)\"" >> "$OUTPUT_FILE"
        fi
    done < "$TUNNEL_ENDPOINTS_FILE"
fi

# Optional endpoints (port 443 TCP) - deduplicated
if [ -f "$OPTIONAL_ENDPOINTS_FILE" ]; then
    sort -u "$OPTIONAL_ENDPOINTS_FILE" | while IFS='|' read -r host port protocols section ipv4s; do
        if echo "$protocols" | grep -qi "tcp"; then
            echo "    \"${host},${port},TCP,Optional - ${host} (HTTPS)\"" >> "$OUTPUT_FILE"
        fi
    done
fi

# Always add DNS checks
echo '    "1.1.1.1,53,UDP,Cloudflare DNS (1.1.1.1)"' >> "$OUTPUT_FILE"
echo '    "1.0.0.1,53,UDP,Cloudflare DNS (1.0.0.1)"' >> "$OUTPUT_FILE"
echo ')' >> "$OUTPUT_FILE"
echo '' >> "$OUTPUT_FILE"

cat >> "$OUTPUT_FILE" << 'SCRIPT_NC'
for test_case in "${tests[@]}"; do
    hostname=$(echo "$test_case" | cut -d',' -f1)
    port=$(echo "$test_case" | cut -d',' -f2)
    protocol=$(echo "$test_case" | cut -d',' -f3)
    description=$(echo "$test_case" | cut -d',' -f4)

    echo -n "  Testing $hostname:$port ($protocol) - $description..."

    is_successful=false
    nc_cmd=""
    nc_output=""

    if [ "$protocol" == "UDP" ]; then
        nc_cmd="nc -uvz -w 3 $hostname $port"
        nc_output=$(nc -uvz -w 3 "$hostname" "$port" 2>&1)
        [ $? -eq 0 ] && is_successful=true
    elif [ "$protocol" == "TCP" ]; then
        nc_cmd="nc -vz -w 3 $hostname $port"
        nc_output=$(nc -vz -w 3 "$hostname" "$port" 2>&1)
        [ $? -eq 0 ] && is_successful=true
    else
        echo -e " ${RED}Unknown protocol '$protocol'. Skipping.${NC}"
        continue
    fi

    if [ "$is_successful" == true ]; then
        echo -e " ${GREEN}PASSED${NC}"
    else
        echo -e " ${RED}FAILED${NC}"
    fi

    if [ "$VERBOSE" == true ]; then
        echo -e "    ${CYAN}> $nc_cmd${NC}"
        if [ -n "$nc_output" ]; then
            echo "$nc_output" | while IFS= read -r line; do echo "      $line"; done
        fi
    fi
done

echo -e "\n${YELLOW}All tests complete.${NC}"
SCRIPT_NC

# Make it executable
chmod +x "$OUTPUT_FILE"

# --- Step 4: Summary ---
echo -e "${CYAN}[4/4]${NC} Done!"
echo ""
echo -e "${GREEN}Generated: ${OUTPUT_FILE}${NC}"
echo -e "  Tunnel endpoints:   ${TUNNEL_COUNT} entries"
echo -e "  Optional endpoints: ${OPTIONAL_COUNT} entries"
echo -e "  DNS hosts to check: ${DNS_COUNT} hosts"
echo -e "  + 2 Cloudflare DNS resolver checks (1.1.1.1, 1.0.0.1)"
echo ""
echo -e "Run it with:"
echo -e "  ${CYAN}./${OUTPUT_FILE}${NC}"
echo -e "  ${CYAN}./${OUTPUT_FILE} -v -o results.txt${NC}"
echo ""

# Cleanup
rm -rf "$TMPDIR"

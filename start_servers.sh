#!/bin/bash
# start_servers.sh
# Starts all 8 servers each in their own Terminal window.
# Uses .command files opened via `open` — no special permissions required.

DIR="$(cd "$(dirname "$0")" && pwd)"
TMPDIR_CMDS=$(mktemp -d /tmp/kerberos_servers_XXXX)

# Creates a .command file and opens it in a new Terminal window
new_window() {
    local label="$1"
    local cmd="$2"
    local f="$TMPDIR_CMDS/${label}.command"
    printf '#!/bin/bash\ncd "%s"\n%s\n' "$DIR" "$cmd" > "$f"
    chmod +x "$f"
    open "$f"
    sleep 0.3
}

echo "🔐  Starting Kerberos Multi-Sig Servers..."
echo "    Project: $DIR"
echo ""

new_window "AS1"         "python3 as_node.py AS1 5001"            && echo "  [1/8]  AS1          → port 5001  ✓"
new_window "AS2"         "python3 as_node.py AS2 5002"            && echo "  [2/8]  AS2          → port 5002  ✓"
new_window "AS3"         "python3 as_node.py AS3 5003"            && echo "  [3/8]  AS3          → port 5003  ✓"
new_window "TGS1"        "python3 tgs_node.py TGS1 6001"          && echo "  [4/8]  TGS1         → port 6001  ✓"
new_window "TGS2"        "python3 tgs_node.py TGS2 6002"          && echo "  [5/8]  TGS2         → port 6002  ✓"
new_window "TGS3"        "python3 tgs_node.py TGS3 6003"          && echo "  [6/8]  TGS3         → port 6003  ✓"
new_window "file_server" "python3 service_server.py file_server 7001"  && echo "  [7/8]  file_server  → port 7001  ✓"
new_window "print_server" "python3 service_server.py print_server 7002" && echo "  [8/8]  print_server → port 7002  ✓"

echo ""
echo "✅  All 8 servers started in separate Terminal windows."
echo ""
echo "══════════════════════════════════════════════════════════"
echo "  Run in THIS terminal:"
echo ""
echo "  Legitimate user:"
echo "    python3 client.py alice file_server"
echo "    python3 client.py alice file_server --loop   # re-auth every 10s"
echo ""
echo "  Attack simulation:"
echo "    python3 attacks.py"
echo "══════════════════════════════════════════════════════════"


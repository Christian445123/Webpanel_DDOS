#!/usr/bin/env bash
#
# VSRP DDoS Monitor - Agent-Installer fuer Linux (systemd).
# Fuer alle Server identisch, nur der Server-Schluessel (vsrv_...) unterscheidet sich.
#
#   curl -fsSL https://ddos.viennastaterp.at/agent/install.sh | sudo bash -s -- vsrv_XXXXXXXX
#   sudo bash install.sh vsrv_XXXXXXXX [https://andere-zentrale.example]
#   sudo bash install.sh --uninstall
#
# Der Agent misst nur (Bandbreite, Pakete/s, Verbindungen, SYN-RECV, Top-IPs) und meldet die Werte an die
# Zentrale. Er veraendert weder Firewall noch Netzwerk und blockiert nichts.

set -euo pipefail

DEFAULT_URL="https://ddos.viennastaterp.at"
CONF="/etc/vsrp-agent.conf"
LIB_DIR="/usr/local/lib/vsrp-agent"
UNIT="/etc/systemd/system/vsrp-agent.service"
SVC_USER="vsrp-agent"

die() { echo "FEHLER: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Bitte als root ausfuehren (sudo)."
command -v systemctl >/dev/null || die "systemd wird benoetigt."

if [ "${1:-}" = "--uninstall" ]; then
    systemctl disable --now vsrp-agent 2>/dev/null || true
    rm -f "$UNIT" "$CONF"
    rm -rf "$LIB_DIR"
    systemctl daemon-reload
    id "$SVC_USER" >/dev/null 2>&1 && userdel "$SVC_USER" 2>/dev/null || true
    echo "VSRP-Agent entfernt."
    exit 0
fi

KEY="${1:-}"
URL="${2:-${DDOS_URL:-$DEFAULT_URL}}"
URL="${URL%/}"
[[ "$KEY" =~ ^vsrv_[0-9a-f]{20,}$ ]] || die "Server-Schluessel fehlt oder ist ungueltig. Aufruf: install.sh vsrv_XXXXXXXX"

# Abhaengigkeiten pruefen, fehlende nach Moeglichkeit nachinstallieren
missing=()
command -v curl >/dev/null || missing+=(curl)
command -v ss   >/dev/null || missing+=(iproute2)
command -v awk  >/dev/null || missing+=(gawk)
if [ "${#missing[@]}" -gt 0 ]; then
    echo "Installiere fehlende Pakete: ${missing[*]}"
    if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq "${missing[@]}"
    elif command -v dnf >/dev/null; then dnf install -y -q "${missing[@]/iproute2/iproute}"
    elif command -v yum >/dev/null; then yum install -y -q "${missing[@]/iproute2/iproute}"
    else die "Bitte manuell installieren: ${missing[*]}"; fi
fi

# Netzwerkschnittstelle mit der Standardroute erkennen
IFACE="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
[ -n "$IFACE" ] || IFACE="$(ip -o link show | awk -F': ' '$2!="lo"{print $2; exit}')"
[ -n "$IFACE" ] || die "Netzwerkschnittstelle nicht erkannt."

id "$SVC_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"

umask 077
cat > "$CONF" <<EOF
URL="$URL"
KEY="$KEY"
IFACE="$IFACE"
INTERVAL=10
EOF
chown root:"$SVC_USER" "$CONF"
chmod 640 "$CONF"
umask 022

mkdir -p "$LIB_DIR"
chmod 755 "$LIB_DIR"
cat > "$LIB_DIR/agent.sh" <<'AGENT_EOF'
#!/usr/bin/env bash
# VSRP DDoS Monitor Agent - misst lokal und meldet an die Zentrale. Blockiert nichts.
set -u
# shellcheck disable=SC1091
. /etc/vsrp-agent.conf

HOST="$(hostname -f 2>/dev/null || hostname)"
HOST="$(printf '%s' "$HOST" | tr -cd 'A-Za-z0-9._-')"
ENDPOINT="$URL/api/index.php?r=agent/report"

read_dev() {
    awk -v i="$IFACE" '{sub(/:/," ")} $1==i {print $2, $3, $10, $11; exit}' /proc/net/dev
}

prev=""
prev_t=""
last_ok=1

while true; do
    now="$(date +%s.%N)"
    cur="$(read_dev)"

    metrics="0 0 0 0"
    if [ -n "$prev" ] && [ -n "$cur" ]; then
        metrics="$(awk -v p="$prev" -v c="$cur" -v t0="$prev_t" -v t1="$now" 'BEGIN {
            split(p, a, " "); split(c, b, " "); dt = t1 - t0; if (dt < 0.5) dt = 0.5
            for (i = 1; i <= 4; i++) { d[i] = b[i] - a[i]; if (d[i] < 0) d[i] = 0 }
            printf "%.3f %d %.3f %d", d[1]*8/1000000/dt, d[2]/dt, d[3]*8/1000000/dt, d[4]/dt
        }')"
    fi
    [ -n "$cur" ] && { prev="$cur"; prev_t="$now"; }
    read -r mbit_in pps_in mbit_out pps_out <<< "$metrics"

    conn_out="$(ss -Htan 2>/dev/null | awk '
        $1 == "LISTEN" { next }
        {
            p = $5
            if (p ~ /^\[/) { ip = p; sub(/^\[/, "", ip); sub(/\]:[0-9*]+$/, "", ip) }
            else { ip = p; sub(/:[0-9*]+$/, "", ip) }
            sub(/^::ffff:/, "", ip)
            if (ip == "" || ip == "*") next
            if (ip ~ /^(127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0|172\.(1[6-9]|2[0-9]|3[01])\.|::1$|fe80|fc|fd)/) next
            total++; c[ip]++
            if ($1 == "SYN-RECV") { syn++; s[ip]++ }
        }
        END { print "T", total + 0, syn + 0; for (i in c) print "I", i, c[i], s[i] + 0 }')"

    read -r _ total_conn syn_recv < <(printf '%s\n' "$conn_out" | awk '$1 == "T"')
    per_ip="$(printf '%s\n' "$conn_out" | awk '$1 == "I"' | sort -k3,3nr | head -25 | awk '
        BEGIN { printf "{" }
        { printf "%s\"%s\":{\"conn\":%d,\"syn\":%d}", (NR > 1 ? "," : ""), $2, $3, $4 }
        END { printf "}" }')"

    [ -n "$per_ip" ] || per_ip="{}"
    json="$(printf '{"hostname":"%s","mbit_in":%s,"pps_in":%s,"mbit_out":%s,"pps_out":%s,"total_conn":%s,"syn_recv":%s,"per_ip":%s}' \
        "$HOST" "${mbit_in:-0}" "${pps_in:-0}" "${mbit_out:-0}" "${pps_out:-0}" "${total_conn:-0}" "${syn_recv:-0}" "$per_ip")"

    code="$(curl -sS -m 8 -o /dev/null -w '%{http_code}' -X POST \
        -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
        --data-binary "$json" "$ENDPOINT" 2>/dev/null || echo 000)"

    if [ "$code" = "200" ]; then
        [ "$last_ok" -eq 1 ] || echo "Verbindung zur Zentrale wiederhergestellt."
        last_ok=1
    elif [ "$last_ok" -eq 1 ]; then
        echo "Meldung an die Zentrale fehlgeschlagen (HTTP $code)." >&2
        last_ok=0
    fi

    sleep "${INTERVAL:-10}"
done
AGENT_EOF
chmod 755 "$LIB_DIR/agent.sh"

cat > "$UNIT" <<UNIT_EOF
[Unit]
Description=VSRP DDoS Monitor Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
ExecStart=$LIB_DIR/agent.sh
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT_EOF

# Rechte sicherstellen (auch bei Neuinstallation ueber eine bestehende Installation) und pruefen, dass der
# Dienstbenutzer die Dateien wirklich lesen/ausfuehren darf - sonst startet der Dienst nicht (Status 203/EXEC).
chown -R root:root "$LIB_DIR"
chmod 755 "$LIB_DIR" "$LIB_DIR/agent.sh"
if command -v runuser >/dev/null; then
    runuser -u "$SVC_USER" -- test -x "$LIB_DIR/agent.sh"         || die "Der Benutzer $SVC_USER darf $LIB_DIR/agent.sh nicht ausfuehren (Rechte der uebergeordneten Ordner oder noexec-Mount pruefen: mount | grep noexec)."
    runuser -u "$SVC_USER" -- test -r "$CONF"         || die "Der Benutzer $SVC_USER darf $CONF nicht lesen."
fi
systemctl daemon-reload
systemctl enable --now vsrp-agent
systemctl restart vsrp-agent

# Dienst pruefen: laeuft er stabil (kein Neustart-Loop)?
sleep 6
state="$(systemctl is-active vsrp-agent || true)"
restarts="$(systemctl show vsrp-agent -p NRestarts --value 2>/dev/null || echo 0)"
if [ "$state" != "active" ] || [ "${restarts:-0}" -gt 0 ]; then
    echo "FEHLER: Der Agent laeuft nicht stabil (Status: $state, Neustarts: ${restarts:-0}). Letzte Logzeilen:" >&2
    journalctl -u vsrp-agent -n 15 --no-pager >&2 || true
    exit 1
fi

# Verbindungstest (Schluessel und Erreichbarkeit der Zentrale)
code="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $KEY" \
    -H 'Content-Type: application/json' --data-binary '{"hostname":"install-test"}' \
    "$URL/api/index.php?r=agent/report" 2>/dev/null || echo 000)"
case "$code" in
    200) echo "OK: Agent laeuft (Schnittstelle $IFACE) und die Zentrale antwortet." ;;
    401) echo "WARNUNG: Die Zentrale lehnt den Schluessel ab (401). Schluessel pruefen." ;;
    *)   echo "WARNUNG: Zentrale nicht erreichbar oder Fehler (HTTP $code). Log: journalctl -u vsrp-agent -f" ;;
esac

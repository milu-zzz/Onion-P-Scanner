#!/usr/bin/env bash

DEFAULT_TIMEOUT=8
DEFAULT_ATTEMPTS=2

SED_FILTERS='
    /^\[proxychains\]/d;
    /RTTVAR has grown/d;
    /adjust_timeouts2:/d;
    /packet supposedly had rtt/d;
    /Unable to resolve/d
'

COMMON_PORTS=(21 22 25 80 110 143 443 587 3306 5432 8080 8443 9001 27017)
LOGFILE="portscans.log"

shopt -s extglob 2>/dev/null || true

err() {
    printf '\033[4;31mError\033[4;37m: %b\033[0m\n' "$1" >&2
}

missing_deps() {
    local miss=()
    for cmd in proxychains4 ncat nmap timeout stdbuf sed awk tor; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            miss+=( "$cmd" )
        fi
    done
    echo "${miss[@]-}"
}

cleanup_on_exit() {
    if [ "${TOR_LAUNCHED:-0}" -eq 1 ] && [ -n "${TOR_PID:-}" ]; then
        if kill -0 "$TOR_PID" >/dev/null 2>&1; then
            kill "$TOR_PID" >/dev/null 2>&1 || true
            sleep 0.5
            kill -9 "$TOR_PID" >/dev/null 2>&1 || true
        fi
    fi
    if [ -n "${SPINNER_PID:-}" ]; then
        kill "$SPINNER_PID" 2>/dev/null || true
        wait "$SPINNER_PID" 2>/dev/null || true
        unset SPINNER_PID
    fi
    [ -f "$PORTFILE" ] && rm -f "$PORTFILE"
    printf '\r\033[2K'
    if [ "$SAVE_LOG" -eq 1 ] && [ "${#OPEN_PORTS[@]}" -gt 0 ]; then
        printf '\nCancelled by user, ports logged. Exiting.\n'
    else
        printf '\nCancelled by user, exiting.\n'
    fi
    exit 1
}

tor_is_reachable() {
    if command -v ncat >/dev/null 2>&1; then
        timeout 1 ncat -z 127.0.0.1 9050 >/dev/null 2>&1 && return 0
        timeout 1 ncat -z 127.0.0.1 9150 >/dev/null 2>&1 && return 0
    fi
    if command -v nc >/dev/null 2>&1; then
        timeout 1 nc -z 127.0.0.1 9050 >/dev/null 2>&1 && return 0
        timeout 1 nc -z 127.0.0.1 9150 >/dev/null 2>&1 && return 0
    fi
    return 1
}

ensure_tor_running() {
    if tor_is_reachable; then
        return 0
    fi
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl start tor 2>/dev/null; then
            sleep 0.5
            tor_is_reachable && return 0
        fi
        if command -v sudo >/dev/null 2>&1; then
            if sudo systemctl start tor 2>/dev/null; then
                sleep 0.5
                tor_is_reachable && return 0
            fi
        fi
    fi
    if command -v service >/dev/null 2>&1; then
        if service tor start 2>/dev/null; then
            sleep 0.5
            tor_is_reachable && return 0
        fi
        if command -v sudo >/dev/null 2>&1; then
            if sudo service tor start 2>/dev/null; then
                sleep 0.5
                tor_is_reachable && return 0
            fi
        fi
    fi
    nohup tor >/dev/null 2>&1 &
    TOR_PID=$!
    sleep 1.5
    if tor_is_reachable; then
        TOR_LAUNCHED=1
        return 0
    fi
    err "unable to start Tor locally.\n"
    exit 3
}

touch_logfile() {
    : > /dev/null
    if [ ! -f "$LOGFILE" ]; then
        : > "$LOGFILE" 2>/dev/null || { err "unable to create log file $LOGFILE\n"; return 1; }
    fi
}

ensure_log_header() {
    touch_logfile || return 1
    if ! grep -Fxq "$TARGET" "$LOGFILE" 2>/dev/null; then
        {
            printf '\n%s\n' "--------------------------------"
            printf '%s\n' "$TARGET"
            printf '%s\n' "--------------------------------"
        } >> "$LOGFILE"
        LOG_HEADER_WRITTEN=1
    else
        LOG_HEADER_WRITTEN=1
    fi
}

port_already_logged() {
    local portnum="$1"
    [ ! -s "$LOGFILE" ] && return 1
    awk -v tgt="$TARGET" -v p="$portnum" '
        $0 == tgt { inblock = 1; next }
        inblock && NF == 0 { exit 1 }
        inblock {
            if ($0 ~ ("^" p "([[:space:]]|\\(|$)")) exit 0
        }
        END { exit 1 }
    ' "$LOGFILE"
}

write_open_port_to_log() {
    local line="$1"
    local portnum="${line%%[[:space:]]*}"
    touch_logfile || return 1
    ensure_log_header || return 1
    if port_already_logged "$portnum"; then
        return 0
    fi
    printf '%s\n' "$line" >> "$LOGFILE"
    return 0
}

REPEAT_CHAR() {
    local char=$1 count=$2
    printf '%*s' "$count" '' | sed "s/ /$char/g"
}

spinner() {
    local frames=('|' '/' '-' '\')
    local i=0
    local prev_line=""
    local last_port=""
    local last_total=""
    while :; do
        if [ -f "$PORTFILE" ]; then
            if read -r line < "$PORTFILE" 2>/dev/null && [ -n "$line" ]; then
                prev_line="$line"
            fi
        fi
        if [ -n "$prev_line" ]; then
            set -- $prev_line
            current_port="$1"
            current_total="${2:-}"
            last_port="$current_port"
            last_total="$current_total"
        else
            current_port="$last_port"
            current_total="$last_total"
        fi
        i=$(( (i + 1) % 4 ))
        if [ -n "$current_total" ]; then
            display="${current_port}/${current_total}"
        else
            display="${current_port:-}"
        fi
        printf '\r\033[2K\tScanning port '"$ORANGE"'%s'"$RESET"' [%s]' "$display" "${frames[i]}"
        sleep 0.5
    done
}

trap cleanup_on_exit INT

deps_missing=$(missing_deps)
if [ -n "$deps_missing" ]; then
    err "the following required commands are not installed or not in PATH:"
    for d in $deps_missing; do
        printf '  - %s\n' "$d" >&2
    done
    printf '\n' >&2
    printf 'Please install them and re-run.\n' >&2
    exit 2
fi

ensure_tor_running

TOR_CMD="proxychains4"
USERNAME="$(id -un 2>/dev/null || echo "${USER:-unknown}")"
PLAIN_WELCOME_MSG="Welcome, $USERNAME"
COLORED_USERNAME=$'\033[1;36m'"$USERNAME"$'\033[0m'
WELCOME_MSG="Welcome, $COLORED_USERNAME"
BANNER_WIDTH=81

TOP_BANNER=$(cat <<'EOF'
   ____        _                ____       _____                                 
  / __ \____  (_)___  ____     / __ \     / ___/_________ _____  ____  ___  _____
 / / / / __ \/ / __ \/ __ \   / /_/ /_____\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
/ /_/ / / / / / /_/ / / / /  / ____/_____/__/ / /__/ /_/ / / / / / / /  __/ /    
\____/_/ /_/_/\____/_/ /_/  /_/         /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
EOF
)

MIN_BOX_WIDTH=32
DYNAMIC_BOX_WIDTH=$(( ${#PLAIN_WELCOME_MSG} + 4 ))
if (( DYNAMIC_BOX_WIDTH > MIN_BOX_WIDTH )); then
  WELCOME_BOX_WIDTH=$DYNAMIC_BOX_WIDTH
else
  WELCOME_BOX_WIDTH=$MIN_BOX_WIDTH
fi
LEFT_PADDING=$(( (BANNER_WIDTH - (WELCOME_BOX_WIDTH + 2)) / 2 ))
LEFT_PADDING_SPACES=$(printf '%*s' "$LEFT_PADDING" '')
INNER_PADDING=$(( WELCOME_BOX_WIDTH - ${#PLAIN_WELCOME_MSG} ))
PADDING_LEFT=$(( INNER_PADDING / 2 ))
PADDING_RIGHT=$(( INNER_PADDING - PADDING_LEFT ))
WELCOME_TOP="${LEFT_PADDING_SPACES}╔$(REPEAT_CHAR '═' "$WELCOME_BOX_WIDTH")╗"
WELCOME_BOT="${LEFT_PADDING_SPACES}╚$(REPEAT_CHAR '═' "$WELCOME_BOX_WIDTH")╝"
WELCOME_MID="${LEFT_PADDING_SPACES}║$(printf '%*s' "$PADDING_LEFT" '')${WELCOME_MSG}$(printf '%*s' "$PADDING_RIGHT" '')║"

clear
echo "$TOP_BANNER"
echo
echo "$WELCOME_TOP"
echo "$WELCOME_MID"
echo -e "$WELCOME_BOT\n"

while true; do
    read -rp $'╔═\033[0;35mEnter target onion url\033[0m (e.x: abcdefg.onion)\n╚════> ' TARGET
    TARGET="${TARGET##*( )}"
    TARGET="${TARGET%%*( )}"
    if [ -z "$TARGET" ]; then
        err 'Please enter a .onion address (cannot be empty).\n'
        continue
    fi
    if [[ ! "${TARGET,,}" =~ \.onion$ ]]; then
        err "target must end with '.onion'.\n"
        continue
    fi
    break
done

SCAN_COMMON=0
while true; do
    read -rp $'╔═\033[0;35mEnter start of port range\033[0m, or type "!" to scan common ports (80, 443, 22, etc)\n╚════> ' START
    START="${START##*( )}"
    START="${START%%*( )}"
    if [ -z "$START" ]; then
        err "please enter a starting port or ! for common ports.\n"
        continue
    fi
    if [ "$START" = "!" ]; then
        SCAN_COMMON=1
        break
    fi
    if ! [[ "$START" =~ ^[0-9]+$ ]]; then
        err "please enter a starting port or ! for common ports..\n"
        continue
    fi
    if [ "$START" -lt 1 ] || [ "$START" -gt 65535 ]; then
        err "start of port range must be between 1 and 65535.\n"
        continue
    fi
    break
done

if [ "$SCAN_COMMON" -eq 0 ]; then
    while true; do
        read -rp $'╔═\033[0;35mEnter end of port range\033[0m\n╚════> ' END
        if ! [[ "$END" =~ ^[0-9]+$ ]]; then
            err "ending port must be a number.\n"
            continue
        fi
        if [ "$END" -lt 1 ] || [ "$END" -gt 65535 ]; then
            err "ending port must be between 1 and 65535.\n"
            continue
        fi
        if [ "$END" -lt "$START" ]; then
            err "ending port must be greater than or equal to start port.\n"
            continue
        fi
        break
    done
fi

while true; do
    read -rp $'╔═\033[0;35mPer-attempt timeout in seconds\033[0m (blank to use default 8s) — \033[0;33monly edit if you know what you\'re doing\033[0m\n╚════> ' TMP_TIMEOUT
    TMP_TIMEOUT="${TMP_TIMEOUT##*( )}"
    TMP_TIMEOUT="${TMP_TIMEOUT%%*( )}"
    if [ -z "$TMP_TIMEOUT" ]; then
        TIMEOUT=$DEFAULT_TIMEOUT
        break
    fi
    if ! [[ "$TMP_TIMEOUT" =~ ^[0-9]+$ ]]; then
        err "timeout must be a whole number of seconds (or blank).\n"
        continue
    fi
    if [ "$TMP_TIMEOUT" -lt 1 ] || [ "$TMP_TIMEOUT" -gt 120 ]; then
        err "timeout must be between 1 and 120 seconds.\n"
        continue
    fi
    TIMEOUT=$TMP_TIMEOUT
    break
done

while true; do
    read -rp $'╔═\033[0;35mAttempts per port\033[0m (blank to use default 2) — \033[0;33monly edit if you know what you\'re doing\033[0m\n╚════> ' TMP_ATTEMPTS
    TMP_ATTEMPTS="${TMP_ATTEMPTS##*( )}"
    TMP_ATTEMPTS="${TMP_ATTEMPTS%%*( )}"
    if [ -z "$TMP_ATTEMPTS" ]; then
        ATTEMPTS_COUNT=$DEFAULT_ATTEMPTS
        break
    fi
    if ! [[ "$TMP_ATTEMPTS" =~ ^[0-9]+$ ]]; then
        err "attempts must be a whole number (or blank).\n"
        continue
    fi
    if [ "$TMP_ATTEMPTS" -lt 1 ] || [ "$TMP_ATTEMPTS" -gt 10 ]; then
        err "attempts must be between 1 and 10.\n"
        continue
    fi
    ATTEMPTS_COUNT=$TMP_ATTEMPTS
    break
done

while true; do
    read -rp $'╔═\033[0;35mSave open ports to file?\033[0m (y/n)\n╚════> ' SAVE_CHOICE
    SAVE_CHOICE="${SAVE_CHOICE##*( )}"
    SAVE_CHOICE="${SAVE_CHOICE%%*( )}"
    if [ -z "$SAVE_CHOICE" ]; then
        SAVE_CHOICE="n"
    fi
    case "${SAVE_CHOICE,,}" in
        y|n) break ;;
        *) err "please enter y or n.\n" ;;
    esac
done

if [ "${SAVE_CHOICE,,}" = "y" ]; then
    SAVE_LOG=1
else
    SAVE_LOG=0
fi

PORTS=()
if [ "$SCAN_COMMON" -eq 1 ]; then
    PORTS=( "${COMMON_PORTS[@]}" )
else
    for ((p=START; p<=END; p++)); do
        PORTS+=( "$p" )
    done
fi

RED=$'\033[0;31m'
PURPLE=$'\033[0;35m'
RESET=$'\033[0m'
ORANGE=$'\033[0;33m'
GREEN=$'\033[0;32m'

SUMMARY_COLORED_LINES=()
SUMMARY_COLORED_LINES+=("Target: ${RED}$TARGET${RESET}")

if [ "$SCAN_COMMON" -eq 1 ]; then
    if [ "${#PORTS[@]}" -le 10 ]; then
        ports_colored="${PURPLE}${PORTS[*]}${RESET}"
    else
        ports_colored="${PURPLE}${PORTS[0]}${RESET} ... ${PURPLE}${PORTS[-1]} ${RESET}(common ports)"
    fi
    SUMMARY_COLORED_LINES+=("Ports: ${ports_colored}")
else
    range_colored="${PURPLE}$START${RESET} - ${PURPLE}$END${RESET}"
    SUMMARY_COLORED_LINES+=("Port range: ${range_colored}")
fi

timeout_colored="${PURPLE}${TIMEOUT}s ${RESET}(default ${DEFAULT_TIMEOUT}s)"
SUMMARY_COLORED_LINES+=("Timeout per attempt: ${timeout_colored}")

attempts_colored="${PURPLE}${ATTEMPTS_COUNT} ${RESET}(default ${DEFAULT_ATTEMPTS})"
SUMMARY_COLORED_LINES+=("Attempts per port: ${attempts_colored}")

if [ "$SAVE_LOG" -eq 1 ]; then
    save_colored="${GREEN}yes${RESET}"
else
    save_colored="${RED}no${RESET}"
fi
SUMMARY_COLORED_LINES+=("Save open ports to file: ${save_colored}")

MAX_SUMMARY_LEN=0
for line in "${SUMMARY_COLORED_LINES[@]}"; do
    plain=$(echo -e "$line" | sed 's/\x1b\[[0-9;]*m//g')
    [ ${#plain} -gt $MAX_SUMMARY_LEN ] && MAX_SUMMARY_LEN=${#plain}
done

MIN_SUMMARY_WIDTH=32
SUMMARY_BOX_WIDTH=$(( MAX_SUMMARY_LEN + 4 ))
if (( SUMMARY_BOX_WIDTH < MIN_SUMMARY_WIDTH )); then
    SUMMARY_BOX_WIDTH=$MIN_SUMMARY_WIDTH
fi

SUMMARY_LEFT_PADDING=$(( (BANNER_WIDTH - (SUMMARY_BOX_WIDTH + 2)) / 2 ))
SUMMARY_LEFT_PAD_SPACES=$(printf '%*s' "$SUMMARY_LEFT_PADDING" '')
SUMMARY_TOP="${SUMMARY_LEFT_PAD_SPACES}╔$(REPEAT_CHAR '═' "$SUMMARY_BOX_WIDTH")╗"
SUMMARY_BOT="${SUMMARY_LEFT_PAD_SPACES}╚$(REPEAT_CHAR '═' "$SUMMARY_BOX_WIDTH")╝"

SUMMARY_MID_LINES=()
for line in "${SUMMARY_COLORED_LINES[@]}"; do
    plain=$(echo -e "$line" | sed 's/\x1b\[[0-9;]*m//g')
    padding=$(( SUMMARY_BOX_WIDTH - ${#plain} ))
    pad_left=$(( padding / 2 ))
    pad_right=$(( padding - pad_left ))
    padded_line="${SUMMARY_LEFT_PAD_SPACES}║$(printf '%*s' "$pad_left" '')${line}$(printf '%*s' "$pad_right" '')║"
    SUMMARY_MID_LINES+=( "$padded_line" )
done

clear
echo "$TOP_BANNER"
echo
echo "$WELCOME_TOP"
echo "$WELCOME_MID"
echo "$WELCOME_BOT"
echo
echo "$SUMMARY_TOP"
for l in "${SUMMARY_MID_LINES[@]}"; do
    echo "$l"
done
echo "$SUMMARY_BOT"
echo

read -rp $'Press Enter to start the scan, or Ctrl + C to cancel...\n' _ENTER
SECONDS=0

total=${#PORTS[@]}
i=0
OPEN_PORTS=()
LOG_HEADER_WRITTEN=0

PORTFILE="/tmp/onion_scan_current_port.$$"
printf '%s\n' "" > "$PORTFILE"
spinner &
SPINNER_PID=$!

for p in "${PORTS[@]}"; do
    if [ "$SCAN_COMMON" -eq 1 ]; then
        printf '%s\n' "$p" > "$PORTFILE"
    else
        printf '%s %s\n' "$p" "$END" > "$PORTFILE"
    fi
    ((i++))
    ok=0
    for attempt in $(seq 1 "$ATTEMPTS_COUNT"); do
        out=$( $TOR_CMD timeout "$TIMEOUT" ncat --verbose --wait "$TIMEOUT" "$TARGET" "$p" 2>&1 \
              | sed -u -E "$SED_FILTERS")
        if echo "$out" | grep -Ei --quiet 'succeed|succeeded|open|connected|Ncat: Connection to|succeeded!'; then
            ok=1
            break
        fi
        sleep 0.15
    done
    if [ "$ok" -eq 1 ]; then
        svc=$( $TOR_CMD stdbuf -oL nmap -sT -Pn -p"$p" -sV --max-retries 1 --min-rate 1 -oG - "$TARGET" 2>/dev/null \
              | awk -F'Ports: ' '/Ports:/{ split($2,ports,","); split(ports[1],f,"/"); print (f[5]!=""?f[5]:"unknown"); exit }')
        printf '\r\033[2K\033[0;32m\tPort OPEN: %d (%s)\033[0m\n' "$p" "$svc"
        OPEN_PORTS+=( "$p ($svc)" )
        if [ "$SAVE_LOG" -eq 1 ]; then
            write_open_port_to_log "$p ($svc)" || {
                printf '\033[0;33mWarning: failed to write to log %s\033[0m\n' "$LOGFILE" >&2
            }
        fi
    fi
done

if [ -n "${SPINNER_PID:-}" ]; then
    kill "$SPINNER_PID" 2>/dev/null || true
    wait "$SPINNER_PID" 2>/dev/null || true
    unset SPINNER_PID
fi
[ -f "$PORTFILE" ] && rm -f "$PORTFILE"
printf '\r\033[2K'

if [ "$SAVE_LOG" -eq 1 ] && [ "${#OPEN_PORTS[@]}" -gt 0 ]; then
    printf '' >> "$LOGFILE"
fi

if [ -n "${SPINNER_PID:-}" ]; then
    kill "$SPINNER_PID" 2>/dev/null || true
    wait "$SPINNER_PID" 2>/dev/null || true
    unset SPINNER_PID
fi
[ -f "$PORTFILE" ] && rm -f "$PORTFILE"
printf '\r\033[2K'

mins=$((SECONDS / 60))
secs=$((SECONDS % 60))
if [ "$mins" -gt 0 ]; then
    if [ "$SAVE_LOG" -eq 1 ] && [ "${#OPEN_PORTS[@]}" -gt 0 ]; then
        printf '\nScan complete | Ports logged | Elapsed time: %d minute(s) %d second(s)\n' "$mins" "$secs"
    else
        printf '\nScan complete | Elapsed time: %d minute(s) %d second(s)\n' "$mins" "$secs"
    fi
else
    if [ "$SAVE_LOG" -eq 1 ] && [ "${#OPEN_PORTS[@]}" -gt 0 ]; then
        printf '\nScan complete | Ports logged | Elapsed time: %d second(s)\n' "$secs"
    else
        printf '\nScan complete | Elapsed time: %d second(s)\n' "$secs"
    fi
fi

if [ "$SAVE_LOG" -eq 1 ] && [ "${#OPEN_PORTS[@]}" -eq 0 ]; then
    :
fi

exit 0
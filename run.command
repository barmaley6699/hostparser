#!/bin/zsh

# Определяем рабочую директорию
CDIR=$(dirname "$0")
cd "$CDIR"

# Файлы
LOCAL_FILE="domainlist.txt"
MERGED_FILE="hosts_merged.txt"

# Цвета
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GRAY='\033[0;90m'
NC='\033[0m'

echo -e "${CYAN}================ MULTI-DNS HOSTS (macOS) ===============${NC}"

get_answer() {
    echo -n -e "$1 [y/n]: "
    read ans
    if [[ "$ans" =~ ^[YyДдНн] ]]; then return 0; else return 1; fi
}

if get_answer "1. Добавить блокировку Adobe?"; then ADD_ADOBE=true; fi
if get_answer "2. Добавить мега-список РЕКЛАМЫ?"; then ADD_ADS=true; fi
if get_answer "3. Открыть папки по завершении?"; then OPEN_PATH=true; fi

echo -e "${CYAN}========================================================${NC}"

# Начало файла
echo "# Generated: $(date)" > "$MERGED_FILE"
typeset -A seen_domains

# Списки URL
ADOBE_URL="https://a.dove.isdumb.one/list.txt"
ADBLOCK_URLS=(
    "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts"
    "https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardDNS.txt"
    "https://adaway.org/hosts.txt"
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"
    "https://v.firebog.net/hosts/Easylist.txt"
    "https://v.firebog.net/hosts/Easyprivacy.txt"
    "https://urlhaus.abuse.ch/downloads/hostfile/"
)

DNS_POOL=("83.220.169.155" "212.109.195.93" "103.27.157.38" "108.165.164.201" "108.165.164.224" "176.99.11.77" "80.78.247.254" "194.190.11.1" "45.155.204.190")

# --- 1. ОБРАБОТКА СПИСКОВ БЛОКИРОВКИ ---
PROCESS_URLS=()
[[ "$ADD_ADOBE" == true ]] && PROCESS_URLS+=("$ADOBE_URL")
[[ "$ADD_ADS" == true ]] && PROCESS_URLS+=("${ADBLOCK_URLS[@]}")

if [[ ${#PROCESS_URLS[@]} -gt 0 ]]; then
    echo -e "\n# === BLOCKLISTS (Adobe, Ads, Malware) ===" >> "$MERGED_FILE"
    echo -e ">>> Обработка списков блокировки..."
    for url in "${PROCESS_URLS[@]}"; do
        echo -n -e "${GRAY}Fetching: ${url##*/}... ${NC}"
        curl -sL --max-time 15 "$url" | while read -r line; do
            domain=$(echo "$line" | sed 's/#.*//' | awk '/^([0-9.]+|::1)?[[:space:]]*[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/ {print $NF}' | tr '[:upper:]' '[:lower:]')
            if [[ -n "$domain" && -z "${seen_domains[$domain]}" ]]; then
                echo "0.0.0.0        $domain" >> "$MERGED_FILE"
                seen_domains[$domain]=1
            fi
        done
        echo -e "${GREEN}Done${NC}"
    done
fi

# --- 2. ПАРСИНГ ТВОЕГО СПИСКА (DOMAINLIST.TXT) ---
if [[ -f "$LOCAL_FILE" ]]; then
    echo -e "\n${CYAN}>>> Processing your domainlist.txt...${NC}"
    typeset -A ping_cache

    # Читаем файл построчно, сохраняя комментарии
    while IFS= read -r line || [[ -n "$line" ]]; do
        trimmed=$(echo "$line" | xargs)
        [[ -z "$trimmed" ]] && continue

        # Если строка — твой комментарий (заголовок сервиса)
        if [[ "$trimmed" == "#"* ]]; then
            echo -e "\n$trimmed" >> "$MERGED_FILE"
            continue
        fi

        # Если это домен
        clean_domain=$(echo "$trimmed" | sed -E 's|^https?://||; s|/.*$||' | tr '[:upper:]' '[:lower:]' | xargs)
        [[ -n "${seen_domains[$clean_domain]}" ]] && continue

        echo -e "\nTarget: $clean_domain"
        best_ip=""
        best_lat=999

        for dns in "${DNS_POOL[@]}"; do
            echo -n -e "  -> DNS $dns... "
            ip=$(dig +short "@$dns" "$clean_domain" | grep -E '^[0-9.]+$' | tail -n1)
            
            if [[ -n "$ip" ]]; then
                if [[ -n "${ping_cache[$ip]}" ]]; then
                    lat=${ping_cache[$ip]}
                    echo -n -e "${GRAY}Found $ip (Cached)${NC}"
                else
                    lat=$(ping -c 1 -t 1 "$ip" 2>/dev/null | awk -F'[=/]' '/time=/ {print $10}' | cut -d. -f1)
                    [[ -z "$lat" ]] && lat=999
                    ping_cache[$ip]=$lat
                    echo -n -e "${GREEN}Found $ip (${lat}ms)${NC}"
                fi
                
                if (( lat < best_lat )); then
                    best_lat=$lat
                    best_ip=$ip
                fi
            else
                echo -n -e "${YELLOW}No IP${NC}"
            fi
            echo ""
        done

        if [[ -n "$best_ip" ]]; then
            printf "%-15s %s\n" "$best_ip" "$clean_domain" >> "$MERGED_FILE"
            seen_domains[$clean_domain]=1
            echo -e "${GREEN}Result: $best_ip${NC}"
        fi
    done < "$LOCAL_FILE"
fi

echo -e "\n${YELLOW}--- ГОТОВО! ---${NC}"
echo -e "Файл создан: ${MERGED_FILE}"

if [[ "$OPEN_PATH" == true ]]; then
    open -R "$MERGED_FILE"
    open "/etc"
fi

echo -e "\n${GRAY}------------------------------------------------${NC}"
if get_answer "Сбросить кэш DNS прямо сейчас? (Потребуется пароль)"; then
    echo "Очистка кэша..."
    sudo killall -HUP mDNSResponder
    echo -e "${GREEN}Кэш DNS успешно очищен!${NC}"
fi
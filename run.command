#!/bin/zsh

# Определяем рабочую директорию
CDIR=$(dirname "$0")
cd "$CDIR"

# Файлы
LOCAL_FILE="domainlist.txt"
CORE_FILE="core_domains.txt"
MERGED_FILE="hosts_merged.txt"

# Цвета
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GRAY='\033[0;90m'
NC='\033[0m'

# Глобальные кэши
typeset -A seen_domains
typeset -A deep_scanned_roots
typeset -A ping_cache

# Дефолтные кор-домены
DEFAULT_CORE=("openai.com" "chatgpt.com" "sora.com" "google.com" "gemini.google" "anthropic.com" "claude.ai" "x.ai" "grok.com" "elevenlabs.io" "codeium.com" "windsurf.com" "deepl.com" "trae.ai" "supercell.com" "epicgames.com" "jetbrains.com" "linear.app" "tidal.com" "deezer.com" "4pda.to" "twitch.tv" "tiktok.com" "badoo.com" "canva.com" "chess.com" "fmhy.net" "patreon.com" "meta.ai" "instagram.com" "facebook.com" "telegram.org" "t.me")

# Загрузка или создание core_domains.txt
if [[ -f "$CORE_FILE" ]]; then
    CORE_DOMAINS=(${(f)"$(grep -v '^#' "$CORE_FILE" | sed '/^$/d')"})
else
    printf "%s\n" "${DEFAULT_CORE[@]}" > "$CORE_FILE"
    CORE_DOMAINS=("${DEFAULT_CORE[@]}")
fi

echo -e "${CYAN}================ MULTI-DNS OPTIMIZED (macOS) ===============${NC}"

get_answer() {
    echo -n -e "$1 [y/n]: "
    read ans
    if [[ "$ans" =~ ^[YyДдНн] ]]; then return 0; else return 1; fi
}

get_external_subdomains() {
    local domain=$1
    echo -e "  ${GRAY}[Deep Scan] Searching subdomains for $domain...${NC}"
    curl -sL --max-time 15 "https://crt.sh/?q=%.$domain&output=json" | \
    grep -oE '"name_value":"[^"]+"' | \
    cut -d'"' -f4 | \
    tr ' ' '\n' | \
    grep -v '\*' | \
    sort -u
}

if get_answer "1. Добавить блокировку Adobe?"; then ADD_ADOBE=true; fi
if get_answer "2. Добавить списки РЕКЛАМЫ (StevenBlack, Firebog)?"; then ADD_ADS=true; fi
if get_answer "3. Включить ВЫБОРОЧНЫЙ ГЛУБОКИЙ ПОИСК?"; then DEEP_SCAN=true; fi
if get_answer "4. Открыть папки по завершении?"; then OPEN_PATH=true; fi

echo -e "${CYAN}========================================================${NC}"

# Подготовка файла
echo "# Generated: $(date)" > "$MERGED_FILE"

# Настройки DNS и внешние ссылки
DNS_POOL=("83.220.169.155" "212.109.195.93" "103.27.157.38" "108.165.164.201" "108.165.164.224")
ADOBE_URL="https://a.dove.isdumb.one/list.txt"
ADBLOCK_URLS=("https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts" "https://v.firebog.net/hosts/Easyprivacy.txt")

# --- 1. ВНЕШНИЕ СПИСКИ (0.0.0.0) ---
PROCESS_URLS=()
[[ "$ADD_ADOBE" == true ]] && PROCESS_URLS+=("$ADOBE_URL")
[[ "$ADD_ADS" == true ]] && PROCESS_URLS+=("${ADBLOCK_URLS[@]}")

for url in "${PROCESS_URLS[@]}"; do
    echo -n -e "${GRAY}Fetching: ${url##*/}... ${NC}"
    curl -sL --max-time 15 "$url" | while read -r line; do
        domain=$(echo "$line" | sed 's/#.*//' | awk '/^([0-9.]+|::1)?[[:space:]]*[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/ {print $NF}' | tr '[:upper:]' '[:lower:]')
        if [[ -n "$domain" && -z "${seen_domains[$domain]}" ]]; then
            echo "0.0.0.0         $domain" >> "$MERGED_FILE"
            seen_domains[$domain]=1
        fi
    done
    echo -e "${GREEN}Done${NC}"
done

# --- 2. ПАРСИНГ DOMAINLIST.TXT ---
if [[ -f "$LOCAL_FILE" ]]; then
    echo -e "\n${CYAN}>>> Processing domainlist.txt...${NC}"
    
    while IFS= read -r line || [[ -n "$line" ]]; do
        trimmed=$(echo "$line" | xargs)
        [[ -z "$trimmed" ]] && continue
        if [[ "$trimmed" == "#"* ]]; then
            echo -e "\n$trimmed" >> "$MERGED_FILE"
            continue
        fi

        # Чистый домен
        base_domain=$(echo "$trimmed" | sed -E 's|^https?://||; s|/.*$||' | tr '[:upper:]' '[:lower:]')

        # ОПТИМИЗАЦИЯ: Если домен уже есть в финальном списке, пропускаем его сразу
        [[ -n "${seen_domains[$base_domain]}" ]] && continue

        targets=("$base_domain")
        seen_domains[$base_domain]=1

        # ОПТИМИЗАЦИЯ: Запускаем Deep Scan только если корень в списке и еще не сканировался
        if [[ "$DEEP_SCAN" == true ]]; then
            for core in "${CORE_DOMAINS[@]}"; do
                if [[ "$base_domain" == "$core" && -z "${deep_scanned_roots[$base_domain]}" ]]; then
                    deep_scanned_roots[$base_domain]=1
                    sub_list=$(get_external_subdomains "$base_domain")
                    for sub in ${(f)sub_list}; do
                        if [[ -n "$sub" && -z "${seen_domains[$sub]}" ]]; then
                            targets+=("$sub")
                            seen_domains[$sub]=1
                        fi
                    done
                    break
                fi
            done
        fi

        # Резолв отобранных доменов
        for target in "${targets[@]}"; do
            echo -n -e "Resolving: $target "
            best_ip=""
            best_lat=999

            for dns in "${DNS_POOL[@]}"; do
                ip=$(dig +short "@$dns" "$target" | grep -E '^[0-9.]+$' | tail -n1)
                if [[ -n "$ip" ]]; then
                    # ОПТИМИЗАЦИЯ: Берем задержку из кэша, если IP уже проверяли
                    if [[ -n "${ping_cache[$ip]}" ]]; then
                        lat=${ping_cache[$ip]}
                    else
                        lat=$(ping -c 1 -t 1 "$ip" 2>/dev/null | awk -F'[=/]' '/time=/ {print $10}' | cut -d. -f1)
                        [[ -z "$lat" ]] && lat=999
                        ping_cache[$ip]=$lat
                    fi
                    
                    if (( lat < best_lat )); then
                        best_lat=$lat
                        best_ip=$ip
                    fi
                fi
            done

            if [[ -n "$best_ip" ]]; then
                printf "%-15s %s\n" "$best_ip" "$target" >> "$MERGED_FILE"
                echo -e "${GREEN}OK ($best_ip)${NC}"
            else
                unset "seen_domains[$target]" # Чтобы можно было перерезолвить в след. раз
                echo -e "${YELLOW}Skip${NC}"
            fi
        done
    done < "$LOCAL_FILE"
fi

echo -e "\n${YELLOW}--- ГОТОВО! ---${NC}"
[[ "$OPEN_PATH" == true ]] && { open -R "$MERGED_FILE"; open "/etc"; }

if get_answer "Сбросить кэш DNS?"; then
    sudo killall -HUP mDNSResponder
    echo -e "${GREEN}Кэш очищен!${NC}"
fi
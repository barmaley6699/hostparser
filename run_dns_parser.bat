<# :
@echo off
chcp 65001 >nul
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ([System.IO.File]::ReadAllText('%~f0'))"
pause
exit /b
#>

# ================================================================
#  MULTI-DNS Hosts Parser — DoH Edition
# ================================================================

$scriptStart = Get-Date

# ================================================================
# КОНФИГУРАЦИЯ
# ================================================================
$currentDir = $PSScriptRoot
if (-not $currentDir) {
    try { $currentDir = Split-Path -Parent $MyInvocation.MyCommand.Definition -EA SilentlyContinue } catch {}
}
if (-not $currentDir) { $currentDir = (Get-Location).Path }

$localFile  = Join-Path $currentDir "domainlist.txt"
$coreFile   = Join-Path $currentDir "core_domains.txt"
$mergedFile = Join-Path $currentDir "hosts_merged.txt"

# DoH пул. Каждый сервер опрашивается через DNS-over-HTTPS.
# Fallback на nslookup если DoH недоступен.
# DNS пул.
# ProxyIPs — список IP которые сервер использует для проксирования трафика.
# Если сервер вернул один из своих ProxyIPs для домена — он его проксирует.
# Такой IP имеет наивысший приоритет: берём сразу без HTTP-тестов.
$dnsPool = [ordered]@{
    'GeoHide'   = @{ IP = '194.190.11.1';   ProxyIPs = @('45.155.204.190','95.182.120.241','31.25.239.132') }
    'Comss'     = @{ IP = '83.220.169.155'; ProxyIPs = @('45.155.204.190','95.182.120.241') }
    'Xbox_1'    = @{ IP = '111.88.96.50';   ProxyIPs = @('77.239.114.0','77.239.113.0') }
    'Xbox_2'    = @{ IP = '111.88.96.51';   ProxyIPs = @('77.239.114.0','77.239.113.0') }
    'Mafioznik' = @{ IP = '212.109.195.93'; ProxyIPs = @('45.155.204.190','95.182.120.241','103.27.157.38') }
    'Astra'     = @{ IP = '108.165.164.201';ProxyIPs = @('77.239.114.0','77.239.113.0','45.155.204.190','108.165.164.201') }
}

# Статические hosts — приоритетный источник.
# Первый файл имеет наивысший приоритет (не перезаписывается).
$staticHostsUrls = @(
    "https://raw.githubusercontent.com/ASTRACAT2022/host-DNS/refs/heads/main/base_hosts.txt",
    "https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts",
    "https://freedom.mafioznik.xyz/file/hosts",
    "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts"
)

# IP которые являются прокси bypass-серверов — curl из-за пределов России
# не может их протестировать (000). Это ожидаемо и не является ошибкой.
$knownProxyIPs = @('77.239.114.0','77.239.113.0','45.155.204.190','95.182.120.241',
                   '31.25.239.132','103.27.157.38','108.165.164.201',
                   '31.7.60.154','31.7.60.155','31.7.60.156','31.7.60.157','179.43.148.133')

$adobeUrl = "https://a.dove.isdumb.one/list.txt"

$finalCheckDomains = if (Test-Path $coreFile) {
    @(Get-Content $coreFile -Encoding UTF8 |
      Where-Object { $_.Trim() -and !$_.StartsWith('#') } |
      ForEach-Object { $_.Trim() })
} else {
    @("openai.com","chatgpt.com","google.com","anthropic.com","claude.ai",
      "telegram.org","instagram.com","facebook.com","tiktok.com")
}

# ================================================================
# ХРАНИЛИЩА
# ================================================================
$finalHosts       = New-Object System.Collections.Generic.List[string]
$finalHostsMap    = @{}
$notFoundDomains  = New-Object System.Collections.Generic.List[string]
$discoveredHosts  = New-Object System.Collections.Generic.List[string]
$seenDomains      = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
$deepScannedRoots = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
$staticIpMap      = @{}   # domain -> ip из статических hosts файлов
$userAgent        = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

# ================================================================
# ФУНКЦИИ
# ================================================================

function Format-Duration([int]$sec) {
    if ($sec -lt 60)  { return "${sec}с" }
    $m = [int]($sec / 60); $s = $sec % 60
    if ($m -lt 60)    { return "${m}м ${s}с" }
    $h = [int]($m / 60); $m2 = $m % 60
    return "${h}ч ${m2}м"
}

function Get-Answer($msg) {
    Write-Host "  " -NoNewline
    $ans = Read-Host "$msg [Y/N]"
    return $ans -match "[yYдД]"
}

# DoH запрос (тихий — если не работает, просто падаем на nslookup)
function Resolve-ViaDoH([string]$domain, [string]$dohUrl, [bool]$skipCert) {
    $curlArgs = @('-s', '--max-time', '4', '-H', 'Accept: application/dns-json')
    if ($skipCert) { $curlArgs += '-k' }
    $url = "${dohUrl}?name=${domain}&type=A"
    try {
        $raw = & curl.exe @curlArgs $url 2>$null
        $rawStr = if ($raw -is [array]) { $raw -join '' } else { [string]$raw }
        if (-not $rawStr) { return @() }
        $json = $rawStr | ConvertFrom-Json -EA Stop
        if ($json.Status -ne 0 -or -not $json.Answer) { return @() }
        return @($json.Answer |
            Where-Object { $_.type -eq 1 } |
            ForEach-Object { [string]$_.data.Trim() } |
            Where-Object { $_ -match '^\d{1,3}(?:\.\d{1,3}){3}$' } |
            Where-Object { $_ -notmatch '^(0\.|127\.|169\.254\.)' })
    } catch { return @() }
}

# DNS резолвинг через nslookup
function Resolve-ViaNslookup([string]$domain, [string]$dnsIp) {
    $raw = & nslookup $domain $dnsIp 2>$null | Out-String
    $sections = $raw -split "`r?`n`r?`n"
    $answer   = if ($sections.Count -gt 1) { $sections[1..($sections.Count-1)] -join "`n" } else { $raw }
    return @([regex]::Matches($answer, '(\d{1,3}(?:\.\d{1,3}){3})') |
             ForEach-Object { [string]$_.Groups[1].Value } |
             Where-Object   { $_ -notmatch '^(0\.|127\.|169\.254\.)' })
}

function Resolve-DomainEntry([string]$target) {
    Write-Host "  $target" -ForegroundColor White

    # Приоритет 1: статические hosts
    if ($staticIpMap.ContainsKey($target)) {
        $staticIp = [string]$staticIpMap[$target]
        Write-Host ("    [STATIC] {0}" -f $staticIp) -ForegroundColor Green
        return "$($staticIp.PadRight(15)) $target"
    }

    # Приоритет 2: опрашиваем DNS серверы
    # Ключевая логика:
    #   Если сервер вернул СВОЙ proxy IP — он проксирует этот домен.
    #   Такой ответ надёжнее чем обычный DNS ответ — берём с наивысшим приоритетом.
    $votes      = [System.Collections.Generic.Dictionary[string,int]]::new([System.StringComparer]::Ordinal)
    $proxyVotes = [System.Collections.Generic.Dictionary[string,int]]::new([System.StringComparer]::Ordinal)
    $dnsLog     = [ordered]@{}

    foreach ($name in $dnsPool.Keys) {
        $srv = $dnsPool[$name]

        # Сначала пробуем DoH (тихо), потом nslookup
        $ips = Resolve-ViaDoH $target $srv.DoH $false
        $src = if ($ips.Count -gt 0) { 'DoH' } else {
            $ips = Resolve-ViaNslookup $target $srv.IP
            'nslookup'
        }

        $dnsLog[$name] = @{ IPs = $ips; Src = $src }

        if ($ips.Count -gt 0) {
            $primary = [string]$ips[0]

            # Голосование общее
            if ($votes.ContainsKey($primary)) { $votes[$primary]++ }
            else { $votes[$primary] = 1 }

            # Отдельное голосование только за proxy IP
            if ($srv.ProxyIPs -contains $primary) {
                if ($proxyVotes.ContainsKey($primary)) { $proxyVotes[$primary]++ }
                else { $proxyVotes[$primary] = 1 }
            }
        }
    }

    # Вывод
    foreach ($name in $dnsLog.Keys) {
        $e       = $dnsLog[$name]
        $str     = if ($e.IPs.Count -gt 0) { $e.IPs -join ', ' } else { '—' }
        $isProxy = $e.IPs.Count -gt 0 -and ($dnsPool[$name].ProxyIPs -contains [string]$e.IPs[0])
        $color   = if ($isProxy) { 'Green' } elseif ($e.Src -eq 'DoH') { 'DarkCyan' } else { 'DarkGray' }
        $tag     = if ($isProxy) { '[PROXY]' } else { "[$($e.Src)]" }
        Write-Host ("    [{0,-9}]{1,-9} {2}" -f $name, $tag, $str) -ForegroundColor $color
    }

    if ($votes.Count -eq 0) {
        Write-Host "    => NO IP" -ForegroundColor Red
        return $null
    }

    $chosenIp = $null

    if ($proxyVotes.Count -gt 0) {
        # Есть proxy IP — берём самый популярный среди них
        $bestProxyVotes = ($proxyVotes.Values | Measure-Object -Maximum).Maximum
        $topProxy = New-Object System.Collections.Generic.List[string]
        foreach ($k in @($proxyVotes.Keys)) {
            if ($proxyVotes[$k] -eq $bestProxyVotes) { $topProxy.Add([string]$k) }
        }
        $chosenIp = [string]$topProxy[0]
        Write-Host ("    => PROXY [{0} серверов]: {1}" -f $bestProxyVotes, $chosenIp) -ForegroundColor Magenta
    } else {
        # Нет proxy IP — мажоритарное голосование
        $maxVotes = ($votes.Values | Measure-Object -Maximum).Maximum
        $topList  = New-Object System.Collections.Generic.List[string]
        foreach ($k in @($votes.Keys)) {
            if ($votes[$k] -eq $maxVotes) { $topList.Add([string]$k) }
        }

        if ($topList.Count -eq 1) {
            $chosenIp = [string]$topList[0]
            Write-Host ("    => VOTE [{0}/{1}]: {2}" -f $maxVotes, $dnsPool.Count, $chosenIp) -ForegroundColor Cyan
        } else {
            # Ничья — пинг
            $bestMs = 99999
            foreach ($ip in $topList) {
                $p  = Test-Connection $ip -Count 1 -EA SilentlyContinue
                $ms = if ($p) { [int]$p.ResponseTime } else { 9999 }
                Write-Host ("    [PING] {0,-17} {1}ms" -f $ip, $ms) -ForegroundColor DarkGray
                if ($ms -lt $bestMs) { $bestMs = $ms; $chosenIp = [string]$ip }
            }
            Write-Host ("    => TIE, fastest: {0} ({1}ms)" -f $chosenIp, $bestMs) -ForegroundColor Cyan
        }
    }

    return "$($chosenIp.PadRight(15)) $target"
}

function Get-ExternalSubdomains([string]$rootDomain) {
    Write-Host "    [crt.sh] $rootDomain ..." -NoNewline -ForegroundColor DarkCyan
    $url = "https://crt.sh/?q=%25.$rootDomain&output=json"
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 45 -EA Stop
            $data = $resp.Content | ConvertFrom-Json -EA Stop
            if ($data) {
                $subs = $data |
                    ForEach-Object { ($_.name_value -split "`n") } |
                    Where-Object   { $_ -like "*.$rootDomain" -and $_ -notmatch '\*' } |
                    ForEach-Object { $_.ToLower().Trim() } |
                    Select-Object -Unique
                Write-Host " $($subs.Count) субдоменов" -ForegroundColor DarkGreen
                return $subs
            }
        } catch {
            if ($attempt -lt 3) {
                Write-Host " попытка $attempt/3, ждём 5с..." -ForegroundColor DarkYellow
                Start-Sleep 5
                Write-Host "    [crt.sh] $rootDomain ..." -NoNewline -ForegroundColor DarkCyan
            } else { Write-Host " недоступен" -ForegroundColor Red }
        }
    }
    return @()
}

# ================================================================
# МЕНЮ
# ================================================================
Write-Host ""
Write-Host "  ╔════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║     MULTI-DNS Hosts Parser  [DoH]         ║" -ForegroundColor Cyan
Write-Host "  ╚════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
$addAdobe = Get-Answer "1. Блокировка Adobe?"
$deepScan = Get-Answer "2. Deep Scan новых субдоменов (crt.sh)?"
$openPath = Get-Answer "3. Открыть папку после завершения?"
Write-Host ""

if (Test-Path $localFile) {
    $domainLines = @(Get-Content $localFile -Encoding UTF8 |
                    Where-Object { $_.Trim() -and !$_.Trim().StartsWith('#') })
    $domainCount = $domainLines.Count
    $etaSec = $domainCount * 3   # ~3с: статика мгновенно, DoH быстрее nslookup
    if ($deepScan) {
        $rootCount = @($domainLines | Where-Object { ($_.Trim() -split '\.').Count -eq 2 }).Count
        $etaSec += $rootCount * 45
    }
    Write-Host ("  DoH серверов     : {0}" -f $dnsPool.Count) -ForegroundColor Cyan
    Write-Host ("  Доменов в списке : {0}" -f $domainCount) -ForegroundColor Cyan
    Write-Host ("  Ожидаемое время  : ~{0}" -f (Format-Duration $etaSec)) -ForegroundColor Cyan
    Write-Host ""
}

# ================================================================
# ШАПКА ФАЙЛА
# ================================================================
$finalHosts.Add("# ================================================================")
$finalHosts.Add("# Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$finalHosts.Add("# DoH pool  : $($dnsPool.Keys -join ', ')")
$finalHosts.Add("# ================================================================")

# ================================================================
# ШАГ 1: СТАТИЧЕСКИЕ HOSTS (приоритетный источник)
# ================================================================
Write-Host "[1/4] Загружаем статические hosts файлы..." -ForegroundColor Cyan
$staticCount = 0
foreach ($url in $staticHostsUrls) {
    $name = ($url -split '/')[-1]
    Write-Host ("  {0,-50}" -f $name) -NoNewline -ForegroundColor DarkGray
    try {
        $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 20 -EA Stop
        # Обрабатываем как байты если Content-Type не text (напр. application/octet-stream)
        $rawContent = if ($resp.Content -is [byte[]]) {
            [System.Text.Encoding]::UTF8.GetString($resp.Content)
        } else {
            [string]$resp.Content
        }
        $content = $rawContent -split "`n"
        $count = 0
        foreach ($line in $content) {
            $clean = $line.Split('#')[0].Trim()
            if ($clean -match '^(\d{1,3}(?:\.\d{1,3}){3})\s+([a-z0-9][a-z0-9._-]*\.[a-z]{2,})$') {
                $ip  = [string]$Matches[1]
                $dom = [string]$Matches[2].ToLower()
                if ($ip -notmatch '^(0\.|127\.|169\.254\.)' -and -not $staticIpMap.ContainsKey($dom)) {
                    $staticIpMap[$dom] = $ip
                    $count++
                    $staticCount++
                }
            }
        }
        Write-Host "$count доменов" -ForegroundColor Green
    } catch { Write-Host "ОШИБКА: $($_.Exception.Message)" -ForegroundColor Red }
}
Write-Host ""

# ================================================================
# ШАГ 2: ADOBE BLOCKLIST
# ================================================================
if ($addAdobe) {
    Write-Host "[2/4] Блоклист Adobe..." -ForegroundColor Cyan
    Write-Host ("  {0,-50}" -f ($adobeUrl -split '/')[-1]) -NoNewline -ForegroundColor DarkGray
    try {
        $content = (Invoke-WebRequest -Uri $adobeUrl -UseBasicParsing -TimeoutSec 20 -EA Stop).Content -split "`n"
        $added = 0
        foreach ($line in $content) {
            $clean = $line.Split('#')[0].Trim()
            if ($clean -match '^(?:(?:0\.0\.0\.0|127\.0\.0\.1)\s+)?([a-z0-9][a-z0-9._-]*\.[a-z]{2,})$') {
                $dom = $Matches[1].ToLower()
                if ($seenDomains.Add($dom)) { $finalHosts.Add("0.0.0.0         $dom"); $added++ }
            }
        }
        Write-Host "+$added" -ForegroundColor Green
    } catch { Write-Host "Пропуск" -ForegroundColor Yellow }
    Write-Host ""
}

# ================================================================
# ШАГ 3: DOMAINLIST.TXT
# ================================================================
if (-not (Test-Path $localFile)) {
    Write-Host "ВНИМАНИЕ: domainlist.txt не найден!" -ForegroundColor Yellow
} else {
    Write-Host "[3/4] Резолвим домены..." -ForegroundColor Cyan
    Write-Host "  [STATIC]=из hosts | [DoH]=DNS-over-HTTPS | [nslookup]=fallback" -ForegroundColor DarkGray
    Write-Host ""

    $lines        = Get-Content $localFile -Encoding UTF8
    $processed    = 0; $duplicates = 0; $fromStatic = 0
    $pendingLines = New-Object System.Collections.Generic.List[string]

    foreach ($line in $lines) {
        $trimmed = $line.Trim()

        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) {
            $pendingLines.Add($trimmed)
            continue
        }

        $dom = ($trimmed -replace '^https?://', '' -replace '[/\?#].*$', '').ToLower().Trim()
        if ([string]::IsNullOrEmpty($dom)) { continue }

        if (-not $seenDomains.Add($dom)) { $duplicates++; continue }

        $processed++
        if ($staticIpMap.ContainsKey($dom)) { $fromStatic++ }

        if ($deepScan -and ($dom -split '\.').Count -eq 2 -and $deepScannedRoots.Add($dom)) {
            $subs = Get-ExternalSubdomains $dom
            foreach ($s in $subs) {
                $sLow = $s.ToLower().Trim()
                if ($sLow -and $seenDomains.Add($sLow)) {
                    $entry = Resolve-DomainEntry $sLow
                    if ($null -ne $entry) { $discoveredHosts.Add($entry) }
                    else { $notFoundDomains.Add($sLow) }
                }
            }
        }

        $entry = Resolve-DomainEntry $dom

        if ($null -ne $entry) {
            foreach ($p in $pendingLines) { $finalHosts.Add($p) }
            $pendingLines.Clear()
            $finalHosts.Add($entry)
            $ip = [string](($entry -split '\s+')[0])
            $finalHostsMap[$dom] = $ip
        } else {
            $notFoundDomains.Add($dom)
        }
    }

    Write-Host ""
    Write-Host ("  Обработано : {0}  |  Из статики : {1}  |  Дублей : {2}  |  NOT FOUND : {3}" -f `
        $processed, $fromStatic, $duplicates, $notFoundDomains.Count) -ForegroundColor Cyan
    Write-Host ""
}

# ================================================================
# АППЕНД: Discovered (Deep Scan)
# ================================================================
if ($discoveredHosts.Count -gt 0) {
    $finalHosts.Add("")
    $finalHosts.Add("# ================================================================")
    $finalHosts.Add("# DISCOVERED via crt.sh ($($discoveredHosts.Count) новых субдоменов)")
    $finalHosts.Add("# ================================================================")
    foreach ($e in $discoveredHosts) {
        $finalHosts.Add($e)
        $parts = $e -split '\s+'
        if ($parts.Count -ge 2) { $finalHostsMap[$parts[1]] = [string]$parts[0] }
    }
}

if ($notFoundDomains.Count -gt 0) {
    Write-Host "  NOT FOUND ($($notFoundDomains.Count)):" -ForegroundColor DarkGray
    foreach ($d in ($notFoundDomains | Sort-Object)) { Write-Host ("    {0}" -f $d) -ForegroundColor DarkGray }
    Write-Host ""
}

# ================================================================
# СОХРАНЕНИЕ (до финального теста)
# ================================================================
$finalHosts | Out-File $mergedFile -Encoding UTF8 -Force

# ================================================================
# ШАГ 4: ФИНАЛЬНАЯ ПРОВЕРКА
# curl --resolve: проверяем именно bypass IP.
# Proxy IP (77.239.114.0, 45.155.204.190 и т.д.) не тестируются
# curl-ом снаружи России — помечаем как PROXY (ожидаемо).
# ================================================================
Write-Host "[4/4] Финальная проверка ($($finalCheckDomains.Count) доменов)..." -ForegroundColor Cyan
Write-Host "  PROXY = bypass-прокси, тест curl снаружи РФ невозможен (это норма)" -ForegroundColor DarkGray
Write-Host ""
$ok = 0; $proxy = 0; $fail = 0; $skip = 0

foreach ($site in $finalCheckDomains) {
    $hostsIp = $finalHostsMap[$site]
    $label   = "  [{0,-15}] {1,-42}" -f $hostsIp, $site

    if (-not $hostsIp) {
        Write-Host ("  {0,-60} НЕТ В HOSTS" -f $site) -ForegroundColor DarkGray
        $skip++; continue
    }

    # Bypass proxy IPs — не тестируем curl снаружи, это прокси
    if ($knownProxyIPs -contains $hostsIp) {
        Write-Host ("{0} PROXY" -f $label) -ForegroundColor Cyan
        $proxy++; continue
    }

    $code = (& curl.exe -s -o NUL -I -w "%{http_code}" --max-time 6 -A $userAgent `
             --resolve "${site}:443:${hostsIp}" --resolve "${site}:80:${hostsIp}" `
             "https://$site" 2>$null) -replace '\s', ''

    if ($code -match '^(200|301|302|304|307|308|401|403|405|451)$') {
        Write-Host ("{0} OK  ({1})" -f $label, $code) -ForegroundColor Green; $ok++
    } elseif ($code -match '^(400|5\d{2})$') {
        Write-Host ("{0} WARN ({1})" -f $label, $code) -ForegroundColor Yellow; $fail++
    } else {
        Write-Host ("{0} FAIL ({1})" -f $label, $code) -ForegroundColor Red; $fail++
    }
}

Write-Host ""
Write-Host ("  OK: {0} | PROXY (норма): {1} | FAIL: {2} | Нет в hosts: {3}" -f $ok, $proxy, $fail, $skip) -ForegroundColor Cyan
Write-Host ""

# ================================================================
# ИТОГ
# ================================================================
$elapsed       = (Get-Date) - $scriptStart
$elapsedStr    = Format-Duration ([int]$elapsed.TotalSeconds)
$resolvedCount = @($finalHosts | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' }).Count

Write-Host "  ┌──────────────────────────────────────────────┐" -ForegroundColor Yellow
Write-Host ("  │  Записей в hosts  : {0,-26}│" -f $resolvedCount) -ForegroundColor Yellow
Write-Host ("  │  Из статич. баз   : {0,-26}│" -f $fromStatic) -ForegroundColor Yellow
Write-Host ("  │  Не разрешено     : {0,-26}│" -f $notFoundDomains.Count) -ForegroundColor Yellow
Write-Host ("  │  Время выполнения : {0,-26}│" -f $elapsedStr) -ForegroundColor Yellow
Write-Host "  │  hosts_merged.txt                            │" -ForegroundColor Yellow
Write-Host "  └──────────────────────────────────────────────┘" -ForegroundColor Yellow

if ($openPath) {
    & explorer.exe /select,"$mergedFile"
    & explorer.exe "C:\Windows\System32\drivers\etc"
}
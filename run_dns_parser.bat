<# :
@echo off
chcp 65001 >nul
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ([System.IO.File]::ReadAllText('%~f0'))"
pause
exit /b
#>
#================================================================
# MULTI-DNS Hosts Parser 
#================================================================
$scriptStart = Get-Date
$currentDir = $PSScriptRoot
if (-not $currentDir) { try { $currentDir = Split-Path -Parent $MyInvocation.MyCommand.Definition -EA SilentlyContinue } catch {} }
if (-not $currentDir) { $currentDir = (Get-Location).Path }

$localFile  = Join-Path $currentDir "domainlist.txt"
$coreFile   = Join-Path $currentDir "core_domains.txt"
$mergedFile = Join-Path $currentDir "hosts_merged.txt"
$userAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

$dnsServers = [ordered]@{
    'GeoHide'   = '194.190.11.1'
    'Comss'     = '83.220.169.155'
    'Xbox_1'    = '111.88.96.50'
    'Xbox_2'    = '111.88.96.51'
    'Mafioznik' = '212.109.195.93'
    'Astra'     = '108.165.164.201'
}

$staticHostsUrls = @(
    "https://raw.githubusercontent.com/ASTRACAT2022/host-DNS/refs/heads/main/base_hosts.txt",
    "https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts",
    "https://freedom.mafioznik.xyz/file/hosts",
    "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts",
    "https://raw.githubusercontent.com/HolyLightRU/HolyZapret/refs/heads/main/lists/hosts-list.txt"
)

$finalCheckDomains = if (Test-Path $coreFile) {
    @(Get-Content $coreFile -Encoding UTF8 | Where-Object { $_.Trim() -and !$_.StartsWith('#') } | ForEach-Object { $_.Trim() })
} else {
    @( "openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "telegram.org", "instagram.com", "tiktok.com")
}

#================================================================
# ХРАНИЛИЩА
#================================================================
$staticIpMap  = @{}   
$processedDomains = @{}
$proxyIpSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
@('194.190.11.1','83.220.169.155','111.88.96.50','111.88.96.51',
  '212.109.195.93','108.165.164.201','108.165.164.224',
  '45.155.204.190','95.182.120.241','31.25.239.132','103.27.157.38') |
    ForEach-Object { [void]$proxyIpSet.Add($_) }

#================================================================
# ФУНКЦИИ
#================================================================
function Format-Duration([int]$sec) {
    if ($sec -lt 60) { return "${sec}с" }
    $m = [int]($sec/60); $s = $sec%60
    if ($m -lt 60) { return "${m}м ${s}с" }
    return "$([int]($m/60))ч $($m%60)м"
}

function Get-Answer($msg) { $ans = Read-Host "  $msg [Y/N]"; return $ans -match "[yYдД]" }

# HTTP проверка (0 = недоступно, >0 = код ответа)
function Test-SiteViaIp([string]$site, [string]$ip, [int]$timeout = 8) {
    $code = (& curl.exe -s -o NUL -w "%{http_code}" -L -k --max-time $timeout `
             --resolve "${site}:443:${ip}" --resolve "${site}:80:${ip}" `
             "https://${site}" 2>$null) -replace '\s', ''
    $intCode = 0
    if ([int]::TryParse($code, [ref]$intCode)) { return $intCode }
    return 0
}

function Resolve-ViaNslookup([string]$domain, [string]$dnsIp) {
    try {
        $raw = & nslookup $domain $dnsIp 2>$null | Out-String
        return @([regex]::Matches($raw, '\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b') | 
                 ForEach-Object { $_.Groups[1].Value } |
                 Where-Object { $_ -notmatch '^(0\.|127\.|169.254\.)' } | Select-Object -Unique)
    } catch { return @() }
}

# Умное наследование IP от родителя
function Get-InheritedIp([string]$domain, [hashtable]$map) {
    $parts = $domain -split '\.'
    for ($i = 1; $i -lt $parts.Count - 1; $i++) {
        $parent = ($parts[$i..($parts.Count-1)] -join '.')
        if ($map.ContainsKey($parent)) { return $map[$parent] }
    }
    return $null
}

#================================================================
# МЕНЮ
#================================================================
Write-Host " "; Write-Host "  ╔════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║     MULTI-DNS Hosts Parser                 ║" -ForegroundColor Cyan
Write-Host "  ╚════════════════════════════════════════════╝" -ForegroundColor Cyan; Write-Host " "

$addAdobe = Get-Answer "1. Блокировка Adobe?"
$deepScan = Get-Answer "2. Deep Scan (crt.sh) - (Медленно)"
$openPath = Get-Answer "3. Открыть папку после завершения?"

if ($deepScan) { Write-Host "  [!] Deep scan включен." -ForegroundColor Yellow }
Write-Host " "

if (Test-Path $localFile) {
    $dc = @(Get-Content $localFile -Encoding UTF8 | Where-Object { $_.Trim() -and !$_.Trim().StartsWith('#') }).Count
    Write-Host ("  DNS серверов : {0} | Доменов : {1}" -f $dnsServers.Count, $dc) -ForegroundColor Cyan; Write-Host ""
}

#================================================================
# ШАГ 1: ЗАГРУЗКА СТАТИКИ
#================================================================
Write-Host "[1/4] Загрузка статических баз..." -ForegroundColor Cyan
foreach ($url in $staticHostsUrls) {
    try {
        $raw = (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15 -EA Stop).Content
        foreach ($line in ($raw -split "`n")) {
            if ($line -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([a-z0-9._-]+\.[a-z]{2,})$') {
                $ip = $Matches[1]; $dom = $Matches[2].ToLower()
                if ($ip -notmatch '^(0\.|127\.)') {
                    if (-not $staticIpMap.ContainsKey($dom)) { $staticIpMap[$dom] = New-Object System.Collections.Generic.List[string] }
                    if (-not $staticIpMap[$dom].Contains($ip)) {
                        $staticIpMap[$dom].Add($ip)
                        [void]$proxyIpSet.Add($ip)
                    }
                }
            }
        }
    } catch {}
}
Write-Host ("  Найдено IP в базах: {0}" -f $staticIpMap.Count) -ForegroundColor DarkGray; Write-Host ""

#================================================================
# ШАГ 2: ОБРАБОТКА DOMAINLIST (Load Balance + Inheritance)
#================================================================
Write-Host "[2/4] Обработка domainlist.txt (Проверка + Балансировка)..." -ForegroundColor Cyan
Write-Host "  Проверяем до 3 кандидатов, выбираем случайный." -ForegroundColor DarkGray; Write-Host ""

if (Test-Path $localFile) {
    $domains = Get-Content $localFile -Encoding UTF8 | Where-Object { $_.Trim() -and !($_.Trim().StartsWith('#')) }
    
    foreach ($rawDom in $domains) {
        $dom = ($rawDom -replace '^https?://', '' -replace '[/?#].*$', '').ToLower().Trim()
        if ([string]::IsNullOrEmpty($dom)) { continue }

        $finalIp = $null
        $source = ""

        # 1. Статика (с балансировкой нагрузки)
        if ($staticIpMap.ContainsKey($dom)) {
            $candidates = @($staticIpMap[$dom] | Where-Object { $proxyIpSet.Contains($_) })
            if ($candidates.Count -eq 0) { $candidates = @($staticIpMap[$dom]) }

            $working = New-Object System.Collections.Generic.List[string]
            $toTest = [Math]::Min($candidates.Count, 5)
            for ($i = 0; $i -lt $toTest; $i++) {
                $code = Test-SiteViaIp $dom $candidates[$i]
                if ($code -gt 0) { $working.Add($candidates[$i]) }
            }

            if ($working.Count -gt 0) {
                $finalIp = $working | Get-Random
                $source = "STATIC (Balanced)"
            } elseif ($candidates.Count -gt 0) {
                $finalIp = $candidates[0]
                $source = "STATIC (Skip Check)"
            }
        }

        # 2. DNS
        if (-not $finalIp) {
            $votes = @{}
            foreach ($dnsName in $dnsServers.Keys) {
                $ips = Resolve-ViaNslookup $dom $dnsServers[$dnsName]
                if ($ips.Count -gt 0) { $ip = $ips[0]; $votes[$ip] = ($votes[$ip] + 1) }
            }
            if ($votes.Count -gt 0) {
                $best = $votes.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
                $finalIp = $best.Name
                $source = "DNS"
            } else {
                $inherited = Get-InheritedIp $dom $processedDomains
                if ($inherited) { $finalIp = $inherited; $source = "INHERITED" }
            }
        }

        if ($finalIp) {
            $processedDomains[$dom] = $finalIp
            $color = if ($source -match "STATIC") { 'Green' } elseif ($source -match "INHERIT") { 'Magenta' } else { 'Cyan' }
            Write-Host "  [$source] $dom -> $finalIp" -ForegroundColor $color
        } else {
            Write-Host "  [FAIL]      $dom" -ForegroundColor DarkGray
        }
    }
}
Write-Host ""

#================================================================
# ШАГ 3: CORE_DOMAINS + BRUTEFORCE
#================================================================
Write-Host "[3/4] Проверка Core + Bruteforce..." -ForegroundColor Cyan
$ok=0; $warn=0; $fail=0; $bruteFound=0
$proxyList = @($proxyIpSet) 

foreach ($site in $finalCheckDomains) {
    $site = $site.ToLower().Trim()
    
    if ($processedDomains.ContainsKey($site)) {
        $ip = $processedDomains[$site]
        $code = Test-SiteViaIp $site $ip 10
        
        $statusText = "ERR"
        $color = 'Red'
        
        if ($code -match '^(200|301|302|403|405|451)$') { 
            $statusText = "OK"; $color = 'Green'; $ok++ 
        } elseif ($code -gt 0) { 
            $statusText = "WRN"; $color = 'Yellow'; $warn++ 
        } else { 
            $fail++ 
        }

        Write-Host ("  [{0,-3}] {1,-42} -> {2}" -f $statusText, $site, $ip) -ForegroundColor $color
    } 
    else {
        Write-Host ("  [SCAN] {0,-42} ... поиск ..." -f $site) -ForegroundColor Yellow
        $foundIp = $null
        
        foreach ($pip in $proxyList) {
            $code = Test-SiteViaIp $site $pip
            if ($code -match '^(200|301|302|403|405)$') { 
                $foundIp = $pip; break 
            }
        }

        if ($foundIp) {
            $processedDomains[$site] = $foundIp
            $bruteFound++
            Write-Host ("       => FOUND: {0}" -f $foundIp) -ForegroundColor Cyan
        } else {
            Write-Host "       => NONE WORK" -ForegroundColor Red
        }
    }
}
Write-Host ""
Write-Host ("  Результат: OK: {0} | Bruteforce Found: {1} | Fail/Skip: {2}" -f $ok, $bruteFound, $fail) -ForegroundColor Cyan
Write-Host ""

#================================================================
# ШАГ 4: ЗАПИСЬ ФАЙЛА (СТРУКТУРА СОХРАНЕНА)
#================================================================
Write-Host "[4/4] Генерация hosts_merged.txt..." -ForegroundColor Cyan
$outLines = New-Object System.Collections.Generic.List[string]
$outLines.Add("# ================================================================")
$outLines.Add("# Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$outLines.Add("# Mode      : Structure Preserved + Load Balanced")
$outLines.Add("# ================================================================")
$outLines.Add("")

$writtenDomains = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

# Проходимся по оригинальному файлу, сохраняя комментарии и пустые строки
if (Test-Path $localFile) {
    foreach ($line in (Get-Content $localFile -Encoding UTF8)) {
        $trimmed = $line.Trim()
        
        # Пустые строки и комментарии (разделы) пишем как есть
        if ([string]::IsNullOrWhiteSpace($trimmed)) { $outLines.Add(""); continue }
        if ($trimmed.StartsWith('#')) { $outLines.Add($trimmed); continue }

        $dom = ($trimmed -replace '^https?://', '' -replace '[/\?#].*$', '').ToLower().Trim()
        if ([string]::IsNullOrEmpty($dom)) { continue }

        # Дедупликация
        if (-not $writtenDomains.Add($dom)) { continue }

        # Если IP найден в шаге 2 или 3
        if ($processedDomains.ContainsKey($dom)) {
            $ip = [string]$processedDomains[$dom]
            # Жесткая проверка формата IP перед записью
            if ($ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                # PadRight безопаснее чем -f, не крашится на спецсимволах
                $outLines.Add($ip.PadRight(20) + $dom)
            }
        }
        # Если IP не найден - пропускаем строку (не ломая структуру сверху/снизу)
    }
}

$outLines | Out-File $mergedFile -Encoding UTF8 -Force

$elapsed = (Get-Date) - $scriptStart
$sec = [int]$elapsed.TotalSeconds
$finalCount = ($outLines | Where-Object { $_ -match '^\d{1,3}\.' }).Count
Write-Host ("  Готово за {0}с | Записей: {1}" -f $sec, $finalCount) -ForegroundColor Yellow
if ((Test-Path "hosts_merged.txt") -and (Get-Item "hosts_merged.txt").Length -gt 1KB) {
    & explorer.exe /select,"$mergedFile"
}
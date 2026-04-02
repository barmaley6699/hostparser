<# :
@echo off
chcp 65001 >nul
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ([System.IO.File]::ReadAllText('%~f0'))"
pause
exit /b
#>
#================================================================
# MULTI-DNS Hosts Parser v8 (FULL RESTORE + STABLE CORE)
#================================================================
$scriptStart = Get-Date
$currentDir = $PSScriptRoot
if (-not $currentDir) { try { $currentDir = Split-Path -Parent $MyInvocation.MyCommand.Definition -EA SilentlyContinue } catch {} }
if (-not $currentDir) { $currentDir = (Get-Location).Path }

$localFile  = Join-Path $currentDir "domainlist.txt"
$coreFile   = Join-Path $currentDir "core_domains.txt"
$mergedFile = Join-Path $currentDir "hosts_merged.txt"

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

$adobeUrl = "https://a.dove.isdumb.one/list.txt"

$finalCheckDomains = if (Test-Path $coreFile) {
    @(Get-Content $coreFile -Encoding UTF8 | Where-Object { $_.Trim() -and !$_.StartsWith('#') } | ForEach-Object { $_.Trim() })
} else {
    @( "openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "telegram.org", "instagram.com", "tiktok.com")
}

#================================================================
# ХРАНИЛИЩА
#================================================================
$staticIpMap      = @{}   
$processedDomains = @{}
$adobeDomains     = @{}
$crtFoundDomains  = New-Object System.Collections.Generic.List[string]
$seenDomains      = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
$proxyIpSet       = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

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
                 Where-Object { $_ -notmatch '^(0\.|127\.|169\.254\.)' } | Select-Object -Unique)
    } catch { return @() }
}

function Get-InheritedIp([string]$domain, [hashtable]$map) {
    $parts = $domain -split '\.'
    for ($i = 1; $i -lt $parts.Count - 1; $i++) {
        $parent = ($parts[$i..($parts.Count-1)] -join '.')
        if ($map.ContainsKey($parent)) { return $map[$parent] }
    }
    return $null
}

function Get-SubdomainsFromCRT([string]$domain) {
    try {
        $url = "https://crt.sh/?q=%.$domain&output=json"
        $raw = (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 45 -EA Stop).Content
        if (-not $raw) { return @() }
        $json = $raw | ConvertFrom-Json
        return @($json | ForEach-Object { $_.name_value }) | 
               Where-Object { $_ -and $_ -notmatch '\*' } | 
               Select-Object -Unique
    } catch { return @() }
}

#================================================================
# МЕНЮ
#================================================================
Write-Host " "; Write-Host "  ╔════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║     MULTI-DNS Hosts Parser v8              ║" -ForegroundColor Cyan
Write-Host "  ╚════════════════════════════════════════════╝" -ForegroundColor Cyan; Write-Host " "

$addAdobe = Get-Answer "1. Блокировка Adobe?"
$deepScan = Get-Answer "2. Deep Scan субдоменов (crt.sh) - (Медленно)"
$openPath = Get-Answer "3. Открыть папку после завершения?"

if ($deepScan) { Write-Host "  [!] Deep scan включен. Может занять время." -ForegroundColor Yellow }
Write-Host " "

if (Test-Path $localFile) {
    $dc = @(Get-Content $localFile -Encoding UTF8 | Where-Object { $_.Trim() -and !$_.Trim().StartsWith('#') }).Count
    Write-Host "  DNS серверов : " + $dnsServers.Count + " | Доменов : " + $dc -ForegroundColor Cyan; Write-Host ""
}

#================================================================
# ШАГ 1: СТАТИКА
#================================================================
Write-Host "[1/5] Загрузка статических баз..." -ForegroundColor Cyan
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
Write-Host "  Найдено IP в базах: " + $staticIpMap.Count -ForegroundColor DarkGray; Write-Host ""

#================================================================
# ШАГ 2: ADOBE
#================================================================
if ($addAdobe) {
    Write-Host "[2/5] Блоклист Adobe..." -ForegroundColor Cyan
    try {
        $content = (Invoke-WebRequest -Uri $adobeUrl -UseBasicParsing -TimeoutSec 20 -EA Stop).Content -split "`n"
        foreach ($line in $content) {
            $clean = $line.Split('#')[0].Trim()
            if ($clean -match '^(?:(?:0\.0\.0\.0|127\.0\.0\.1)\s+)?([a-z0-9][a-z0-9._-]*\.[a-z]{2,})$') {
                $dom = $Matches[1].ToLower()
                $adobeDomains[$dom] = $true
            }
        }
        Write-Host "  Загружено Adobe доменов: " + $adobeDomains.Count -ForegroundColor Green
    } catch { Write-Host "  Пропуск (ошибка сети)" -ForegroundColor Yellow }
    Write-Host ""
}

#================================================================
# ШАГ 3: DEEP SCAN (CRT.SH)
#================================================================
if ($deepScan -and (Test-Path $coreFile)) {
    Write-Host "[3/5] Deep Scan (crt.sh) для core_domains..." -ForegroundColor Yellow
    Write-Host "  Таймаут: 45с. Пропускаем wildcard (*)..." -ForegroundColor DarkGray; Write-Host ""
    
    $coreList = Get-Content $coreFile -Encoding UTF8 | Where-Object { $_.Trim() -and !($_.Trim().StartsWith('#')) }
    foreach ($dom in $coreList) {
        $dom = $dom.Trim().ToLower()
        Write-Host ("  Сканирую {0} ..." -f $dom) -NoNewline -ForegroundColor Cyan
        $found = Get-SubdomainsFromCRT $dom
        if ($found.Count -gt 0) {
            foreach ($f in $found) {
                if ($seenDomains.Add($f)) { $crtFoundDomains.Add($f) }
            }
            Write-Host (" +{0}" -f $found.Count) -ForegroundColor Green
        } else {
            Write-Host " [0]" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
}

#================================================================
# ШАГ 4: ОБРАБОТКА DOMAINLIST + LOAD BALANCE
#================================================================
Write-Host "[4/5] Резолв domainlist.txt (Балансировка + Наследование)..." -ForegroundColor Cyan
Write-Host "  Проверяем до 3 кандидатов, выбираем случайный." -ForegroundColor DarkGray; Write-Host ""

# Объединяем domainlist и найденное через crt.sh
$domainsToProcess = New-Object System.Collections.Generic.List[string]
if (Test-Path $localFile) {
    Get-Content $localFile -Encoding UTF8 | ForEach-Object { $domainsToProcess.Add($_.Trim().ToLower()) }
}
if ($crtFoundDomains.Count -gt 0) { $domainsToProcess.AddRange($crtFoundDomains) }

foreach ($rawDom in $domainsToProcess) {
    if ([string]::IsNullOrEmpty($rawDom) -or $rawDom.StartsWith('#')) { continue }
    $dom = ($rawDom -replace '^https?://', '' -replace '[/?#].*$', '').Trim()
    if ($seenDomains.Contains($dom)) { continue }
    $seenDomains.Add($dom) | Out-Null

    $finalIp = $null; $source = ""

    # Пропускаем Adobe
    if ($adobeDomains.ContainsKey($dom)) { 
        $processedDomains[$dom] = "127.0.0.1"; $source = "ADOBE_BLOCKED"; continue 
    }

    # 1. Статика
    if ($staticIpMap.ContainsKey($dom)) {
        $candidates = @($staticIpMap[$dom] | Where-Object { $proxyIpSet.Contains($_) })
        if ($candidates.Count -eq 0) { $candidates = @($staticIpMap[$dom]) }
        $working = New-Object System.Collections.Generic.List[string]
        $toTest = [Math]::Min($candidates.Count, 5)
        for ($i = 0; $i -lt $toTest; $i++) {
            if (Test-SiteViaIp $dom $candidates[$i] -gt 0) { $working.Add($candidates[$i]) }
        }
        if ($working.Count -gt 0) {
            $finalIp = $working | Get-Random
            $source = "STATIC (Balanced)"
        } elseif ($candidates.Count -gt 0) {
            $finalIp = $candidates[0]; $source = "STATIC (Unverified)"
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
            $finalIp = $best.Name; $source = "DNS"
        }
    }

    # 3. Наследование
    if (-not $finalIp) {
        $inherited = Get-InheritedIp $dom $processedDomains
        if ($inherited) { $finalIp = $inherited; $source = "INHERITED" }
    }

    if ($finalIp) {
        $processedDomains[$dom] = $finalIp
        $color = if ($source -match "STATIC") { 'Green' } elseif ($source -match "INHERIT") { 'Magenta' } else { 'Cyan' }
        Write-Host "  [$source] $dom -> $finalIp" -ForegroundColor $color
    }
}
Write-Host ""

#================================================================
# ШАГ 5: CORE BRUTEFORCE
#================================================================
Write-Host "[5/5] Финальная проверка core + Bruteforce..." -ForegroundColor Cyan
$ok=0; $bruteFound=0; $proxyList = @($proxyIpSet)

foreach ($site in $finalCheckDomains) {
    $site = $site.ToLower().Trim()
    if ($processedDomains.ContainsKey($site)) {
        $code = Test-SiteViaIp $site $processedDomains[$site] 10
        if ($code -match '^(200|301|302|403|405|451)$') { $ok++ }
    } else {
        foreach ($pip in $proxyList) {
            if (Test-SiteViaIp $site $pip -match '^(200|301|302|403|405)$') {
                $processedDomains[$site] = $pip; $bruteFound++; break
            }
        }
    }
}
Write-Host ("  Core OK: {0} | Bruteforce Found: {1}" -f $ok, $bruteFound) -ForegroundColor Cyan; Write-Host ""

#================================================================
# ШАГ 6: ГЕНЕРАЦИЯ ФАЙЛА (СТРУКТУРА + АВТОДОБАВЛЕНИЕ)
#================================================================
Write-Host "[OUTPUT] Генерация hosts_merged.txt..." -ForegroundColor Cyan
$outLines = New-Object System.Collections.Generic.List[string]
$outLines.Add("# Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$outLines.Add("# Mode      : Full Restore + Structure Preserved")
$outLines.Add("# ================================================================")
$outLines.Add("")

$writtenDomains = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

# 1. Сохраняем оригинальную структуру domainlist.txt
if (Test-Path $localFile) {
    foreach ($line in (Get-Content $localFile -Encoding UTF8)) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { $outLines.Add(""); continue }
        if ($trimmed.StartsWith('#')) { $outLines.Add($trimmed); continue }

        $dom = ($trimmed -replace '^https?://', '' -replace '[/\?#].*$', '').ToLower().Trim()
        if ([string]::IsNullOrEmpty($dom) -or -not $writtenDomains.Add($dom)) { continue }

        if ($processedDomains.ContainsKey($dom)) {
            $ip = [string]$processedDomains[$dom]
            if ($ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                $outLines.Add($ip.PadRight(20) + $dom)
            }
        }
    }
}

# 2. Добавляем найденные через CRT.SH (если их нет в основном файле)
$outLines.Add("")
$outLines.Add("# --- Auto-Discovered (Deep Scan) ---")
$crtAdded = 0
foreach ($dom in $crtFoundDomains) {
    if (-not $writtenDomains.Contains($dom) -and $processedDomains.ContainsKey($dom)) {
        $ip = [string]$processedDomains[$dom]
        if ($ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            $outLines.Add($ip.PadRight(20) + $dom)
            $crtAdded++
        }
    }
}

$outLines | Out-File $mergedFile -Encoding UTF8 -Force

$elapsed = (Get-Date) - $scriptStart
$sec = [int]$elapsed.TotalSeconds
$finalCount = ($outLines | Where-Object { $_ -match '^\d{1,3}\.' }).Count
Write-Host ("  Готово за {0}с | Записей: {1} (Из них CRT: {2})" -f $sec, $finalCount, $crtAdded) -ForegroundColor Yellow
if ($openPath -and (Test-Path $mergedFile)) { & explorer.exe /select,"$mergedFile" }
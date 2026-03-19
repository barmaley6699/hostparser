<# :
@echo off
chcp 65001 >nul
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ([System.IO.File]::ReadAllText('%~f0'))"
pause
exit /b
#>

# --- КОНФИГУРАЦИЯ ---
$currentDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (!$currentDir) { $currentDir = Get-Location }

$dnsPool = [ordered]@{
    'Comss_1'    = '83.220.169.155'; 'Comss_2'    = '212.109.195.93'
    'Serverel'   = '103.27.157.38';  'Astra_1'    = '108.165.164.201'
    'Astra_2'    = '108.165.164.224'; 'Xbox_Main'  = '176.99.11.77'
    'Xbox_Alt'   = '80.78.247.254';  'GeoHide_1'  = '194.190.11.1'
    'GeoHide_2'  = '45.155.204.190'
}

$adobeUrl = "https://a.dove.isdumb.one/list.txt"
$adblockUrls = @(
    "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts",
    "https://raw.githubusercontent.com/r-a-y/mobile-hosts/master/AdguardDNS.txt",
    "https://adaway.org/hosts.txt",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "https://v.firebog.net/hosts/Easylist.txt",
    "https://v.firebog.net/hosts/Easyprivacy.txt",
    "https://urlhaus.abuse.ch/downloads/hostfile/"
)

$localFile  = Join-Path $currentDir "domainlist.txt"
$mergedFile = Join-Path $currentDir "hosts_merged.txt"
$sysHostsDir = "C:\Windows\System32\drivers\etc"

$finalHosts = New-Object System.Collections.Generic.List[string]
$seenDomains = New-Object System.Collections.Generic.HashSet[string]
$finalHosts.Add("# Generated: $(Get-Date)")

function Get-Answer($msg) {
    Write-Host "------------------------------------------------" -ForegroundColor Gray
    $ans = Read-Host "$msg [Y/N]"
    if ($ans.Length -gt 0) { 
        $char = $ans.Substring(0,1).ToLower()
        return ("y", "д", "н") -contains $char 
    }
    return $false
}

Write-Host "================ MULTI-DNS HOSTS ===============" -ForegroundColor Cyan
$addAdobe   = Get-Answer "1. Добавить блокировку Adobe (dove.isdumb.one)?"
$addAds     = Get-Answer "2. Добавить мега-список РЕКЛАМЫ и МАЛВАРИ?"
$openPath   = Get-Answer "3. Открыть папки для ручной замены после завершения?"
Write-Host "================================================" -ForegroundColor Cyan

# --- 1. ОБРАБОТКА СПИСКОВ БЛОКИРОВКИ ---
$urlsToProcess = @()
if ($addAdobe) { $urlsToProcess += $adobeUrl }
if ($addAds)   { $urlsToProcess += $adblockUrls }

if ($urlsToProcess.Count -gt 0) {
    $finalHosts.Add("`n# === BLOCKLISTS (Adobe, Ads, Malware) ===")
}

foreach ($url in $urlsToProcess) {
    Write-Host "Fetching: $($url.Split('/')[-1])... " -NoNewline -ForegroundColor DarkGray
    try {
        $content = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        $lines = $content.Content -split "`n"
        $count = 0
        foreach ($line in $lines) {
            $cleanLine = $line.Split('#')[0].Trim()
            if ($cleanLine.Length -gt 0) {
                if ($cleanLine -match "^(?:(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$") {
                    $domain = $Matches[1].ToLower()
                    if ($seenDomains.Add($domain)) {
                        $finalHosts.Add("0.0.0.0        $domain")
                        $count++
                    }
                }
            }
        }
        Write-Host "Added $count unique domains" -ForegroundColor Green
    } catch { Write-Host "Error fetching list" -ForegroundColor Yellow }
}

# --- 2. ПАРСИНГ ТВОЕГО СПИСКА (DOMAINLIST.TXT) ---
if (Test-Path $localFile) {
    $localDomains = Get-Content $localFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") }
    Write-Host "`n>>> Resolving your domains..." -ForegroundColor Cyan
    
    foreach ($domain in $localDomains) {
        $cleanDomain = ($domain -replace '^https?://', '' -replace '/.*$', '').Split("/")[0].ToLower()
        if ([string]::IsNullOrWhiteSpace($cleanDomain) -or $seenDomains.Contains($cleanDomain)) { continue }

        Write-Host "`nTarget: $cleanDomain" -ForegroundColor White
        $candidates = @()
        $pingCache = @{}

        foreach ($dnsName in $dnsPool.Keys) {
            Write-Host "  -> $dnsName... " -NoNewline -ForegroundColor DarkGray
            try {
                $query = nslookup $cleanDomain $dnsPool[$dnsName] 2>$null
                $ipMatch = $query | Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}" | Select-Object -Last 1
                if ($ipMatch) {
                    $ip = $ipMatch.ToString().Split()[-1]
                    if ($ip -ne $dnsPool[$dnsName] -and $ip -ne "127.0.0.1" -and $ip -ne "0.0.0.0") {
                        if ($pingCache.ContainsKey($ip)) {
                            $latency = $pingCache[$ip]
                            $msg = if ($latency -eq 999) { "No Ping" } else { "$($latency)ms" }
                            Write-Host "Found $ip (Cached: $msg)" -ForegroundColor Gray
                        } else {
                            $ping = Test-Connection -ComputerName $ip -Count 1 -ErrorAction SilentlyContinue
                            $latency = if ($ping) { $ping.ResponseTime } else { 999 }
                            $pingCache[$ip] = $latency
                            $msg = if ($latency -eq 999) { "No Ping" } else { "$($latency)ms" }
                            Write-Host "Found $ip ($msg)" -ForegroundColor DarkGreen
                        }
                        $candidates += [PSCustomObject]@{ IP = $ip; Latency = $latency; DNS = $dnsName }
                    }
                }
            } catch {}
        }

        if ($candidates.Count -gt 0) {
            $best = $candidates | Sort-Object Latency | Select-Object -First 1
            # ВОЗВРАЩАЕМ КРАСИВУЮ РАЗБИВКУ
            $finalHosts.Add("`n# --- $cleanDomain (via $($best.DNS)) ---")
            $finalHosts.Add("$($best.IP.PadRight(15)) $cleanDomain")
            $seenDomains.Add($cleanDomain) | Out-Null
            Write-Host "Result: $($best.IP) via $($best.DNS)" -ForegroundColor Green
        }
    }
}

# --- 3. СОХРАНЕНИЕ И ЗАВЕРШЕНИЕ ---
$finalHosts | Out-File $mergedFile -Encoding utf8
Write-Host "`n--- ГОТОВО! ---" -ForegroundColor Yellow
Write-Host "Файл создан: $mergedFile" -ForegroundColor Gray

if ($openPath) {
    explorer.exe /select,"$mergedFile"
    explorer.exe "$sysHostsDir"
    
    Write-Host "`n[!] Инструкция:" -ForegroundColor Cyan
    Write-Host "1. Скопируй содержимое '$mergedFile'" -ForegroundColor White
    Write-Host "2. Вставь в системный файл hosts ($sysHostsDir\hosts)" -ForegroundColor White
}

Write-Host "`n------------------------------------------------" -ForegroundColor Gray
if (Get-Answer "Сбросить кэш DNS прямо сейчас? (FlushDNS)") {
    ipconfig /flushdns
    Write-Host "Кэш DNS успешно очищен!" -ForegroundColor Green
}
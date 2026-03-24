<# :
@echo off
chcp 65001 >nul
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ([System.IO.File]::ReadAllText('%~f0'))"
pause
exit /b
#>

# --- КОНФИГУРАЦИЯ ПУТЕЙ ---
$currentDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (!$currentDir) { $currentDir = Get-Location }

$localFile       = Join-Path $currentDir "domainlist.txt"
$coreFile        = Join-Path $currentDir "core_domains.txt"
$mergedFile      = Join-Path $currentDir "hosts_merged.txt"

# Дефолтные кор-домены (если файл core_domains.txt отсутствует)
$defaultCore = @(
    "openai.com", "chatgpt.com", "sora.com", "google.com", "gemini.google", "anthropic.com", 
    "claude.ai", "x.ai", "grok.com", "elevenlabs.io", "codeium.com", "windsurf.com", 
    "deepl.com", "trae.ai", "supercell.com", "epicgames.com", "jetbrains.com", 
    "linear.app", "tidal.com", "deezer.com", "4pda.to", "twitch.tv", "tiktok.com", 
    "badoo.com", "canva.com", "chess.com", "fmhy.net", "patreon.com", "meta.ai", 
    "instagram.com", "facebook.com", "telegram.org", "t.me"
)

# Загрузка кор-доменов из файла
if (Test-Path $coreFile) {
    $coreDomains = Get-Content $coreFile | Where-Object { $_ -match "\." -and $_ -notmatch "^#" }
} else {
    $defaultCore | Out-File $coreFile -Encoding utf8
    $coreDomains = $defaultCore
}

# Настройки DNS и списков
$dnsPool = [ordered]@{
    'Comss_1'    = '83.220.169.155'; 'Comss_2'    = '212.109.195.93'
    'Serverel'   = '103.27.157.38';  'Astra_1'    = '108.165.164.201'
    'Astra_2'    = '108.165.164.224'; 'GeoHide_1'  = '194.190.11.1'
    'GeoHide_2'  = '45.155.204.190'
}

$adobeUrl = "https://a.dove.isdumb.one/list.txt"
$adblockUrls = @(
    "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts",
    "https://v.firebog.net/hosts/Easyprivacy.txt"
)

# Глобальные хранилища для оптимизации
$finalHosts = New-Object System.Collections.Generic.List[string]
$seenDomains = New-Object System.Collections.Generic.HashSet[string]
$deepScannedRoots = New-Object System.Collections.Generic.HashSet[string]
$pingCache = @{} # IP -> Latency

$finalHosts.Add("# Generated: $(Get-Date)")

function Get-Answer($msg) {
    Write-Host "------------------------------------------------" -ForegroundColor Gray
    $ans = Read-Host "$msg [Y/N]"
    return $ans -match "[yYдД]"
}

function Get-ExternalSubdomains($domain) {
    Write-Host "  [Deep Scan] Searching subdomains for $domain..." -ForegroundColor DarkCyan
    $url = "https://crt.sh/?q=%.$domain&output=json"
    try {
        $data = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 15 -ErrorAction SilentlyContinue
        if ($data) {
            return $data | ForEach-Object { $_.name_value -split "`n" } | 
                   Where-Object { $_ -like "*.$domain" -and $_ -notmatch "\*" } | 
                   Select-Object -Unique
        }
    } catch {}
    return @()
}

Write-Host "================ MULTI-DNS OPTIMIZED (Windows) ===============" -ForegroundColor Cyan
$addAdobe   = Get-Answer "1. Добавить блокировку Adobe?"
$addAds     = Get-Answer "2. Добавить списки РЕКЛАМЫ?"
$deepScan   = Get-Answer "3. Включить ВЫБОРОЧНЫЙ ГЛУБОКИЙ ПОИСК?"
$openPath   = Get-Answer "4. Открыть папки после завершения?"
Write-Host "==========================================================" -ForegroundColor Cyan

# --- 1. ПРЕДВАРИТЕЛЬНАЯ ЗАГРУЗКА БЛОКЛИСТОВ (0.0.0.0) ---
$urlsToBlock = @()
if ($addAdobe) { $urlsToBlock += $adobeUrl }
if ($addAds)   { $urlsToBlock += $adblockUrls }

foreach ($url in $urlsToBlock) {
    Write-Host "Fetching: $($url.Split('/')[-1])... " -NoNewline -ForegroundColor DarkGray
    try {
        $content = (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15).Content -split "`n"
        $count = 0
        foreach ($line in $content) {
            $clean = $line.Split('#')[0].Trim()
            if ($clean -match "^(?:(?:0\.0\.0\.0|127\.0\.0\.1)\s+)?([a-z0-9.-]+\.[a-z]{2,})$") {
                $domain = $Matches[1].ToLower()
                if ($seenDomains.Add($domain)) {
                    $finalHosts.Add("0.0.0.0         $domain")
                    $count++
                }
            }
        }
        Write-Host "Added $count" -ForegroundColor Green
    } catch { Write-Host "Skip" -ForegroundColor Yellow }
}

# --- 2. ОБРАБОТКА ТВОЕГО СПИСКА ---
if (Test-Path $localFile) {
    Write-Host "`n>>> Processing domainlist.txt..." -ForegroundColor Cyan
    $lines = Get-Content $localFile

    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed.StartsWith("#")) { $finalHosts.Add("`n$trimmed"); continue }

        # Извлекаем чистый домен
        $baseDomain = ($trimmed -replace '^https?://', '' -replace '/.*$', '').Split("/")[0].ToLower()
        
        # ОПТИМИЗАЦИЯ: Если домен уже в итоговом списке (из блоклистов или выше), пропускаем его
        if ($seenDomains.Contains($baseDomain)) { continue }

        $targets = New-Object System.Collections.Generic.List[string]
        $targets.Add($baseDomain)
        $seenDomains.Add($baseDomain) | Out-Null

        # ОПТИМИЗАЦИЯ: Deep Scan только для корней и только если еще не сканировали
        if ($deepScan -and ($coreDomains -contains $baseDomain) -and $deepScannedRoots.Add($baseDomain)) {
            $subs = Get-ExternalSubdomains $baseDomain
            foreach ($s in $subs) {
                if ($seenDomains.Add($s.ToLower())) { $targets.Add($s.ToLower()) }
            }
        }

        # Резолв отобранных целей
        foreach ($target in $targets) {
            Write-Host "Resolving: $target " -NoNewline -ForegroundColor White
            $candidates = @()

            foreach ($dnsName in $dnsPool.Keys) {
                try {
                    $query = nslookup $target $dnsPool[$dnsName] 2>$null
                    $ipMatch = $query | Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}" | Select-Object -Last 1
                    if ($ipMatch) {
                        $ip = $ipMatch.ToString().Split()[-1]
                        if ($ip -match "^\d" -and $ip -ne $dnsPool[$dnsName]) {
                            # ОПТИМИЗАЦИЯ: берем задержку из кэша, если IP уже проверяли
                            if ($pingCache.ContainsKey($ip)) {
                                $lat = $pingCache[$ip]
                            } else {
                                $p = Test-Connection $ip -Count 1 -ErrorAction SilentlyContinue
                                $lat = if ($p) { $p.ResponseTime } else { 999 }
                                $pingCache[$ip] = $lat
                            }
                            $candidates += [PSCustomObject]@{ IP = $ip; Latency = $lat }
                        }
                    }
                } catch {}
            }

            if ($candidates.Count -gt 0) {
                $best = $candidates | Sort-Object Latency | Select-Object -First 1
                $finalHosts.Add("$($best.IP.PadRight(15)) $target")
                Write-Host "OK" -ForegroundColor Green
            } else {
                $seenDomains.Remove($target) | Out-Null # Убираем, чтобы можно было перерезолвить потом
                Write-Host "Skip" -ForegroundColor Yellow
            }
        }
    }
}

$finalHosts | Out-File $mergedFile -Encoding utf8
Write-Host "`n--- ГОТОВО! ---" -ForegroundColor Yellow
if ($openPath) { 
    explorer.exe /select,"$mergedFile"
    explorer.exe "C:\Windows\System32\drivers\etc"
}
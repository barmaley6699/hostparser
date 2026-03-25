<# :
@echo off
chcp 65001 >nul
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ([System.IO.File]::ReadAllText('%~f0'))"
pause
exit /b
#>

# --- 1. КОНФИГУРАЦИЯ ---
$currentDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
if (!$currentDir) { $currentDir = Get-Location }

$localFile       = Join-Path $currentDir "domainlist.txt"
$coreFile        = Join-Path $currentDir "core_domains.txt"
$mergedFile      = Join-Path $currentDir "hosts_merged.txt"

# Дефолтные кор-домены
$defaultCore = @(
    "openai.com", "chatgpt.com", "sora.com", "google.com", "gemini.google", "anthropic.com", 
    "claude.ai", "x.ai", "grok.com", "elevenlabs.io", "codeium.com", "windsurf.com", 
    "deepl.com", "trae.ai", "supercell.com", "epicgames.com", "jetbrains.com", 
    "linear.app", "tidal.com", "deezer.com", "4pda.to", "twitch.tv", "tiktok.com", 
    "badoo.com", "canva.com", "chess.com", "fmhy.net", "patreon.com", "meta.ai", 
    "instagram.com", "facebook.com", "telegram.org", "t.me"
)

if (Test-Path $coreFile) {
    $coreDomains = Get-Content $coreFile | Where-Object { $_ -match "\." -and $_ -notmatch "^#" }
} else {
    $defaultCore | Out-File $coreFile -Encoding utf8
    $coreDomains = $defaultCore
}

$dnsPool = [ordered]@{
    'Comss_1'    = '83.220.169.155'; 'Comss_2'    = '212.109.195.93'
    'Serverel'   = '103.27.157.38';  'Astra_1'    = '108.165.164.201'
    'Astra_2'    = '108.165.164.224'; 'GeoHide_1'  = '194.190.11.1'
}

$adobeUrl = "https://a.dove.isdumb.one/list.txt"
$adblockUrls = @(
    "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts",
    "https://v.firebog.net/hosts/Easyprivacy.txt"
)

# Хранилища данных
$finalHosts = New-Object System.Collections.Generic.List[string]
$seenDomains = New-Object System.Collections.Generic.HashSet[string]
$deepScannedRoots = New-Object System.Collections.Generic.HashSet[string]
$pingCache = @{} # IP -> Latency

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

Write-Host "================ MULTI-DNS + GEO-CHECK (Win) ===============" -ForegroundColor Cyan
$addAdobe   = Get-Answer "1. Добавить блокировку Adobe?"
$addAds     = Get-Answer "2. Добавить списки РЕКЛАМЫ?"
$deepScan   = Get-Answer "3. Включить ВЫБОРОЧНЫЙ ГЛУБОКИЙ ПОИСК?"
$openPath   = Get-Answer "4. Открыть папки после завершения?"
Write-Host "============================================================" -ForegroundColor Cyan

$finalHosts.Add("# Generated: $(Get-Date)")

# --- 2. ЗАГРУЗКА БЛОКЛИСТОВ ---
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

# --- 3. ОБРАБОТКА DOMAINLIST.TXT ---
if (Test-Path $localFile) {
    Write-Host "`n>>> Processing domainlist.txt..." -ForegroundColor Cyan
    $lines = Get-Content $localFile
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed.StartsWith("#")) { $finalHosts.Add("`n$trimmed"); continue }

        $baseDomain = ($trimmed -replace '^https?://', '' -replace '/.*$', '').Split("/")[0].ToLower()
        if ($seenDomains.Contains($baseDomain)) { continue }

        $targets = New-Object System.Collections.Generic.List[string]
        $targets.Add($baseDomain)
        $seenDomains.Add($baseDomain) | Out-Null

        if ($deepScan -and ($coreDomains -contains $baseDomain) -and $deepScannedRoots.Add($baseDomain)) {
            $subs = Get-ExternalSubdomains $baseDomain
            foreach ($s in $subs) {
                if ($seenDomains.Add($s.ToLower())) { $targets.Add($s.ToLower()) }
            }
        }

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
                            if ($pingCache.ContainsKey($ip)) { $lat = $pingCache[$ip] }
                            else {
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
                $seenDomains.Remove($target) | Out-Null
                Write-Host "Skip" -ForegroundColor Yellow
            }
        }
    }
}

$finalHosts | Out-File $mergedFile -Encoding utf8

# --- 4. SMART GEO-CHECK С ПЕРЕБОРОМ IP ---
Write-Host "`n>>> TESTING REAL ACCESS (SMART GEO-CHECK)..." -ForegroundColor Cyan

if (Test-Path $coreFile) {
    $testSites = Get-Content $coreFile | Where-Object { $_ -match "\." -and $_ -notmatch "^#" }
} else {
    $testSites = $defaultCore
}

$failedDomains = New-Object System.Collections.Generic.List[string]

foreach ($site in $testSites) {
    $site = $site.Trim().ToLower()
    if ([string]::IsNullOrWhiteSpace($site)) { continue }

    Write-Host "Testing $site... ".PadRight(35) -NoNewline
    
    # 1. Первая попытка (с текущим IP из hosts)
    $check = curl.exe -I -s --max-time 5 "https://$site" | Select-String "HTTP/"
    
    $isWorking = $false
    if ($check) {
        $code = $check.ToString().Split(' ')[1]
        if ($code -match "200|301|302|204") {
            Write-Host "SUCCESS ($code)" -ForegroundColor Green
            $isWorking = $true
        } else {
            Write-Host "FAILED ($code)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "NO RESPONSE" -ForegroundColor Red
    }

    # 2. Если не сработало — предлагаем найти замену
    if (-not $isWorking) {
        Write-Host "  [!] $site заблокирован. Попробовать другие IP из пула DNS?" -NoNewline -ForegroundColor Cyan
        $choice = Read-Host " [Y/N]"
        if ($choice -match "[yYдД]") {
            Write-Host "  Searching alternatives for $site..." -ForegroundColor DarkGray
            
            # Собираем ВСЕ уникальные IP от всех DNS для этого домена
            $allCandidates = @()
            foreach ($dnsName in $dnsPool.Keys) {
                $q = nslookup $site $dnsPool[$dnsName] 2>$null
                $m = $q | Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}" | Select-Object -Last 1
                if ($m) { 
                    $newIp = $m.ToString().Split()[-1]
                    if ($newIp -match "^\d" -and $newIp -ne $dnsPool[$dnsName]) {
                        $allCandidates += $newIp
                    }
                }
            }
            $allCandidates = $allCandidates | Select-Object -Unique

            $foundNew = $false
            foreach ($altIp in $allCandidates) {
                Write-Host "    Trying IP: $altIp ... " -NoNewline -ForegroundColor DarkGray
                # Тестируем альтернативный IP через curl --resolve
                $altCheck = curl.exe -I -s --max-time 4 --resolve "$($site):443:$altIp" "https://$site" | Select-String "HTTP/"
                
                if ($altCheck -and $altCheck.ToString() -match "200|301|302") {
                    $newCode = $altCheck.ToString().Split(' ')[1]
                    Write-Host "WORKS! ($newCode)" -ForegroundColor Green
                    
                    # ОБНОВЛЯЕМ HOSTS прямо в памяти (или записываем в файл)
                    # Находим строку с этим доменом и меняем IP
                    for ($i=0; $i -lt $finalHosts.Count; $i++) {
                        if ($finalHosts[$i] -match "\s+$site$") {
                            $finalHosts[$i] = "$($altIp.PadRight(15)) $site"
                            break
                        }
                    }
                    $foundNew = $true
                    break
                } else {
                    Write-Host "Failed" -ForegroundColor Red
                }
            }
            if (-not $foundNew) { Write-Host "    [!] Рабочих альтернатив не найдено." -ForegroundColor Red }
        }
    }
}

# Перезаписываем файл, если были исправления
$finalHosts | Out-File $mergedFile -Encoding utf8
Write-Host "`n--- ОБНОВЛЕННЫЙ ФАЙЛ СОХРАНЕН: $mergedFile ---" -ForegroundColor Yellow
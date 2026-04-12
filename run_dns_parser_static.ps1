$scriptStart = Get-Date
$currentDir = $PSScriptRoot
if (-not $currentDir) { $currentDir = (Get-Location).Path }

$localFile = Join-Path $currentDir "domainlist.txt"
$coreFile = Join-Path $currentDir "core_domains.txt"
$mergedFile = Join-Path $currentDir "hosts_merged.txt"

$staticHostsUrls = @(
    "https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts",
    "https://raw.githubusercontent.com/ASTRACAT2022/host-DNS/refs/heads/main/base_hosts.txt",
    "https://freedom.mafioznik.xyz/file/hosts",
    "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts"
)

$adobeUrl = "https://a.dove.isdumb.one/list.txt"
$reMalwackUrl = "https://raw.githubusercontent.com/ZG089/Re-Malwack/refs/heads/hosts-update/hosts"

$probeWindowSec = 12
$probeTimeoutSec = 8
$precheckTimeoutSec = 3
$fullProbeTopIps = 2
$maxCandidateIps = 4
$geoProbeTimeoutSec = 8
$inheritedProbeTimeoutSec = 6
$coreRecoveryMaxIps = 8

$geoBlockPatterns = @(
    "not[\s_-]+available[\s_-]+in[\s_-]+your[\s_-]+country",
    "not[\s_-]+available[\s_-]+in[\s_-]+your[\s_-]+region",
    "unavailable[\s_-]+in[\s_-]+your[\s_-]+country",
    "unavailable[\s_-]+in[\s_-]+your[\s_-]+region",
    "service[\s_-]+is[\s_-]+not[\s_-]+available[\s_-]+in[\s_-]+your[\s_-]+location",
    "content[\s_-]+is[\s_-]+not[\s_-]+available[\s_-]+in[\s_-]+your[\s_-]+country",
    "access[\s_-]+denied[\s_-]+based[\s_-]+on[\s_-]+your[\s_-]+location",
    "unsupported[\s_-]*country",
    "geographic restriction",
    "geo.?block",
    "available[\s_-]+only[\s_-]+in[\s_-]+your[\s_-]+region",
    "available[\s_-]+only[\s_-]+in[\s_-]+selected[\s_-]+countries",
    "because[\s_-]+of[\s_-]+your[\s_-]+location",
    "restricted[\s_-]+in[\s_-]+your[\s_-]+country",
    "region[\s_-]+is[\s_-]+not[\s_-]+supported"
)

$staticIpMap = @{}
$processedDomains = @{}
$adobeDomains = @{}
$reMalwackDomains = @{}
$seenDomains = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
$writtenDomains = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
$proxyIpSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$proxyIpList = New-Object System.Collections.Generic.List[string]

function Format-Duration([int]$sec) {
    if ($sec -lt 60) { return "${sec}s" }
    $m = [int]($sec / 60)
    $s = $sec % 60
    if ($m -lt 60) { return "${m}m ${s}s" }
    return "$([int]($m / 60))h $($m % 60)m"
}

function Get-Answer([string]$msg) {
    while ($true) {
        $ans = (Read-Host "  $msg [Y/N]").Trim().ToLower()

        if ($ans -in @('y', 'yes', 'д', 'да', 'н')) { return $true }
        if ($ans -in @('n', 'no', 'н', 'нет', 'т')) { return $false }

        Write-Host "  Введите Y/N, Да/Нет или символы в другой раскладке." -ForegroundColor Yellow
    }
}

function Normalize-Domain([string]$value) {
    if ([string]::IsNullOrWhiteSpace($value)) { return $null }

    $domain = $value.Trim().ToLower()
    $domain = $domain.Split('#')[0].Trim()
    if (-not $domain) { return $null }

    $domain = $domain -replace '^https?://', ''
    $domain = $domain -replace '[/\?#].*$', ''
    $domain = $domain -replace '^\*\.', ''
    $domain = $domain.Trim(".")
    $domain = $domain.Trim(".")

    if ($domain -match '^[a-z0-9][a-z0-9._-]*\.[a-z]{2,}$') { return $domain }
    return $null
}

function Add-ProxyIp([string]$ip) {
    if ([string]::IsNullOrWhiteSpace($ip)) { return }
    if ($proxyIpSet.Add($ip)) { [void]$proxyIpList.Add($ip) }
}

function Add-DomainIp([hashtable]$map, [string]$domain, [string]$ip) {
    if (-not $domain -or -not $ip) { return }
    if (-not $map.ContainsKey($domain)) {
        $map[$domain] = New-Object System.Collections.Generic.List[string]
    }
    if (-not $map[$domain].Contains($ip)) {
        $map[$domain].Add($ip)
        Add-ProxyIp $ip
    }
}

function Import-HostsContent([string]$content, [hashtable]$targetMap, [switch]$IncludeBlockingTargets) {
    if ([string]::IsNullOrWhiteSpace($content)) { return 0 }

    $added = 0
    foreach ($line in ($content -split "`r?`n")) {
        $clean = $line.Split('#')[0].Trim()
        if (-not $clean) { continue }

        if ($clean -match '^(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<rest>.+)$') {
            $ip = $Matches['ip']
            if (-not $IncludeBlockingTargets -and $ip -match '^(0\.0\.0\.0|127\.)') { continue }

            foreach ($token in ($Matches['rest'] -split '\s+')) {
                $domain = Normalize-Domain $token
                if (-not $domain) { continue }

                if ($IncludeBlockingTargets) {
                    if (-not $targetMap.ContainsKey($domain)) {
                        $targetMap[$domain] = $true
                        $added++
                    }
                } else {
                    $before = if ($targetMap.ContainsKey($domain)) { $targetMap[$domain].Count } else { 0 }
                    Add-DomainIp -map $targetMap -domain $domain -ip $ip
                    if ($targetMap[$domain].Count -gt $before) { $added++ }
                }
            }
        }
    }

    return $added
}

function Test-SiteViaIp([string]$site, [string]$ip, [int]$timeout = 8) {
    $raw = (& curl.exe -s -o NUL -w "%{http_code}|%{time_total}" -L -k --http1.1 `
        --max-time $timeout --connect-timeout ([Math]::Min(6, $timeout)) `
        --resolve "${site}:443:${ip}" --resolve "${site}:80:${ip}" `
        -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HostParser" `
        "https://${site}" 2>$null) -replace '\s', ''

    $statusCode = 0
    $timeTotal = 999.0
    if ($raw) {
        $parts = $raw -split '\|', 2
        if ($parts.Count -ge 1) { [void][int]::TryParse($parts[0], [ref]$statusCode) }
        if ($parts.Count -eq 2) {
            [void][double]::TryParse(
                $parts[1],
                [System.Globalization.NumberStyles]::Float,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [ref]$timeTotal
            )
        }
    }

    [pscustomobject]@{
        StatusCode = $statusCode
        TimeTotal = $timeTotal
    }
}

function Get-CandidateIps([string]$domain, [hashtable]$map, [int]$limit = 8) {
    $result = New-Object System.Collections.Generic.List[string]
    $seen = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::Ordinal)

    $appendIps = {
        param([string[]]$ips)
        foreach ($ip in $ips) {
            if ($seen.Add($ip)) { [void]$result.Add($ip) }
            if ($result.Count -ge $limit) { break }
        }
    }

    if ($map.ContainsKey($domain)) {
        & $appendIps @($map[$domain])
    }

    if ($result.Count -lt $limit) {
        $parts = $domain -split '\.'
        for ($i = 1; $i -lt $parts.Count - 1; $i++) {
            $parent = ($parts[$i..($parts.Count - 1)] -join '.')
            if ($map.ContainsKey($parent)) {
                & $appendIps @($map[$parent])
            }
            if ($result.Count -ge $limit) { break }
        }
    }

    return @($result)
}

function Get-InheritedResolvedIp([string]$domain, [hashtable]$map) {
    $parts = $domain -split '\.'
    for ($i = 1; $i -lt $parts.Count - 1; $i++) {
        $parent = ($parts[$i..($parts.Count - 1)] -join '.')
        if ($map.ContainsKey($parent)) {
            $ip = [string]$map[$parent]
            if ($ip -match '^\d{1,3}(?:\.\d{1,3}){3}$' -and $ip -notmatch '^(0\.0\.0\.0|127\.)') { return $ip }
        }
    }
    return $null
}

function Update-ProbeStat([hashtable]$stat, [pscustomobject]$probe) {
    $stat.Attempts++
    $stat.LatencySum += $probe.TimeTotal

    if ($probe.Reachable) {
        $stat.ReachableCount++
    } elseif ($probe.GeoBlocked) {
        $stat.GeoBlocked++
    } else {
        $stat.Failed++
    }

    if ($probe.StatusCode -gt 0 -and $stat.BestCode -eq 0) {
        $stat.BestCode = $probe.StatusCode
    }

    if ($probe.TimeTotal -lt $stat.BestLatency) {
        $stat.BestLatency = $probe.TimeTotal
        if ($probe.StatusCode -gt 0) { $stat.BestCode = $probe.StatusCode }
    }
}

function Get-ProbeRanking([hashtable]$stats) {
    @(
        $stats.Values |
            Sort-Object `
                @{ Expression = { [int]$_.GeoBlocked }; Descending = $false },
                @{ Expression = { [double]$_.ReachableCount / [Math]::Max([int]$_.Attempts, 1) }; Descending = $true },
                @{ Expression = { [int]$_.ReachableCount }; Descending = $true },
                @{ Expression = { [int]$_.Failed }; Descending = $false },
                @{ Expression = { [double]$_.LatencySum / [Math]::Max([int]$_.Attempts, 1) }; Descending = $false },
                @{ Expression = { [double]$_.BestLatency }; Descending = $false }
    )
}

function Get-ProbeReason([pscustomobject]$probe) {
    if ($probe.GeoBlocked) {
        if ($probe.Location) {
            return ("geo-block ({0}; Location: {1})" -f $probe.Evidence, $probe.Location)
        }
        return ("geo-block ({0})" -f $probe.Evidence)
    }

    if ($probe.StatusCode -gt 0) {
        if ($probe.Location) {
            return ("HTTP {0} (Location: {1})" -f $probe.StatusCode, $probe.Location)
        }
        return ("HTTP {0}" -f $probe.StatusCode)
    }

    return "timeout"
}

function Show-StageProgress([int]$id, [string]$activity, [string]$status, [int]$current, [int]$total) {
    $safeTotal = [Math]::Max($total, 1)
    $percent = [int][Math]::Min(100, [Math]::Floor(($current / [double]$safeTotal) * 100))
    Write-Progress -Id $id -Activity $activity -Status $status -PercentComplete $percent
}

function Show-ChildProgress([int]$id, [int]$parentId, [string]$activity, [string]$status, [double]$current, [double]$total) {
    $safeTotal = [Math]::Max($total, 1.0)
    $percent = [int][Math]::Min(100, [Math]::Floor(($current / $safeTotal) * 100))
    Write-Progress -Id $id -ParentId $parentId -Activity $activity -Status $status -PercentComplete $percent
}

function Complete-ProgressBar([int]$id, [int]$parentId = -1, [string]$activity = "") {
    if ($parentId -ge 0) {
        Write-Progress -Id $id -ParentId $parentId -Activity $activity -Completed
    } else {
        Write-Progress -Id $id -Activity $activity -Completed
    }
}

function Get-ProcessingEstimate(
    [string[]]$rawDomains,
    [string[]]$coreDomains,
    [bool]$includeAdobe,
    [bool]$includeReMalwack
) {
    $uniqueDomains = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    $uniqueCoreDomains = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    $singleCandidateDomains = 0
    $multiCandidateDomains = 0
    $noCandidateDomains = 0
    $blockedDomains = 0
    $totalCandidateIps = 0
    $mainRoughSec = 0
    $mainMaxSec = 0

    $roughMultiIpSec = $precheckTimeoutSec * [Math]::Max(1, [Math]::Min($maxCandidateIps, 2))
    $fullProbeCountForEstimate = [Math]::Min($fullProbeTopIps, $maxCandidateIps)

    foreach ($rawDomain in $rawDomains) {
        $domain = Normalize-Domain $rawDomain
        if (-not $domain) { continue }
        if (-not $uniqueDomains.Add($domain)) { continue }

        if ($includeAdobe -and $adobeDomains.ContainsKey($domain)) {
            $blockedDomains++
            continue
        }

        if ($includeReMalwack -and $reMalwackDomains.ContainsKey($domain)) {
            $blockedDomains++
            continue
        }

        $candidateCount = @(Get-CandidateIps -domain $domain -map $staticIpMap -limit $maxCandidateIps).Count
        if ($candidateCount -le 0) {
            $noCandidateDomains++
            continue
        }

        $totalCandidateIps += $candidateCount
        if ($candidateCount -eq 1) {
            $singleCandidateDomains++
            $mainRoughSec += [Math]::Min($probeTimeoutSec, $probeWindowSec)
            $mainMaxSec += [Math]::Min($probeTimeoutSec, $probeWindowSec)
        } else {
            $multiCandidateDomains++
            $precheckCount = [Math]::Min($candidateCount, $maxCandidateIps)
            $fullProbeCount = [Math]::Min($candidateCount, $fullProbeCountForEstimate)
            $mainRoughSec += ($precheckCount * $precheckTimeoutSec) + ($fullProbeCount * $roughMultiIpSec)
            $mainMaxSec += ($precheckCount * $precheckTimeoutSec) + ($fullProbeCount * $probeWindowSec)
        }
    }

    foreach ($coreDomain in $coreDomains) {
        $normalizedCore = Normalize-Domain $coreDomain
        if ($normalizedCore) { [void]$uniqueCoreDomains.Add($normalizedCore) }
    }

    $coreDomainCount = $uniqueCoreDomains.Count
    $coreRoughPasses = [Math]::Min(3, [Math]::Max(1, $coreRecoveryMaxIps))
    $coreMaxPasses = [Math]::Min($coreRecoveryMaxIps, [Math]::Max(1, $proxyIpList.Count))
    $coreRoughSec = $coreDomainCount * $geoProbeTimeoutSec * $coreRoughPasses
    $coreMaxSec = $coreDomainCount * $geoProbeTimeoutSec * $coreMaxPasses

    [pscustomobject]@{
        UniqueDomainCount = $uniqueDomains.Count
        BlockedDomains = $blockedDomains
        SingleCandidateDomains = $singleCandidateDomains
        MultiCandidateDomains = $multiCandidateDomains
        NoCandidateDomains = $noCandidateDomains
        TotalCandidateIps = $totalCandidateIps
        MainRoughSec = $mainRoughSec
        MainMaxSec = $mainMaxSec
        CoreDomainCount = $coreDomainCount
        CoreRoughSec = $coreRoughSec
        CoreMaxSec = $coreMaxSec
        TotalRoughSec = $mainRoughSec + $coreRoughSec
        TotalMaxSec = $mainMaxSec + $coreMaxSec
    }
}

function Get-PreferredRecoveryIps([string]$site, [string]$currentIp, [string[]]$preferredIps, [int]$limit = 8) {
    $result = New-Object System.Collections.Generic.List[string]
    $seen = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::Ordinal)

    $appendIp = {
        param([string]$ip)
        if (-not $ip) { return }
        if ($ip -eq $currentIp) { return }
        if ($ip -notmatch '^\d{1,3}(?:\.\d{1,3}){3}$') { return }
        if ($ip -match '^(0\.0\.0\.0|127\.)') { return }
        if ($seen.Add($ip)) { [void]$result.Add($ip) }
    }

    foreach ($candidateIp in (Get-CandidateIps -domain $site -map $staticIpMap -limit $maxCandidateIps)) {
        & $appendIp $candidateIp
        if ($result.Count -ge $limit) { return @($result) }
    }

    $inheritedIp = Get-InheritedResolvedIp -domain $site -map $processedDomains
    if ($inheritedIp) {
        & $appendIp $inheritedIp
        if ($result.Count -ge $limit) { return @($result) }
    }

    foreach ($preferredIp in $preferredIps) {
        & $appendIp $preferredIp
        if ($result.Count -ge $limit) { return @($result) }
    }

    foreach ($proxyIp in $proxyIpList) {
        & $appendIp $proxyIp
        if ($result.Count -ge $limit) { return @($result) }
    }

    return @($result)
}

function Is-OutputtableIp([string]$ip) {
    if (-not $ip) { return $false }
    if ($ip -notmatch '^\d{1,3}(?:\.\d{1,3}){3}$') { return $false }
    if ($ip -match '^(0\.0\.0\.0|127\.)') { return $false }
    return $true
}

function Get-OrderedOutputIps([string]$domain, [hashtable]$staticMap, [hashtable]$runtimeMap) {
    $result = New-Object System.Collections.Generic.List[string]
    $seen = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::Ordinal)

    $appendIp = {
        param([string]$ip)
        if (-not (Is-OutputtableIp $ip)) { return }
        if ($seen.Add($ip)) { [void]$result.Add($ip) }
    }

    $runtimeIp = $null
    if ($runtimeMap.ContainsKey($domain)) {
        $candidateRuntimeIp = [string]$runtimeMap[$domain]
        if (Is-OutputtableIp $candidateRuntimeIp) {
            $runtimeIp = $candidateRuntimeIp
            & $appendIp $runtimeIp
        }
    }

    if ($staticMap.ContainsKey($domain)) {
        foreach ($ip in $staticMap[$domain]) {
            & $appendIp ([string]$ip)
        }
    }

    return @($result)
}

function Find-BestCandidate([string]$site, [string[]]$candidateIps, [int]$windowSec = 12, [int]$timeout = 8) {
    $ips = @($candidateIps | Select-Object -Unique | Select-Object -First $maxCandidateIps)
    if ($ips.Count -eq 0) { return $null }

    $stats = @{}
    $phaseTotal = $ips.Count + [Math]::Min($fullProbeTopIps, $ips.Count)
    $phaseDone = 0.0

    foreach ($ip in $ips) {
        $stats[$ip] = [ordered]@{
            Ip = $ip
            Attempts = 0
            ReachableCount = 0
            GeoBlocked = 0
            Failed = 0
            BestCode = 0
            BestLatency = 999.0
            LatencySum = 0.0
        }
    }

    if ($ips.Count -eq 1) {
        Show-ChildProgress -id 2 -parentId 1 -activity ("Подбор IP: {0}" -f $site) -status ("single-check {0}" -f $ips[0]) -current 0 -total 1
        $probe = Test-GeoAvailability -site $site -ip $ips[0] -timeout $timeout
        Update-ProbeStat -stat $stats[$ips[0]] -probe $probe
        Show-ChildProgress -id 2 -parentId 1 -activity ("Подбор IP: {0}" -f $site) -status ("single-check завершён: {0}" -f $ips[0]) -current 1 -total 1
    } else {
        foreach ($ip in $ips) {
            Show-ChildProgress -id 2 -parentId 1 -activity ("Подбор IP: {0}" -f $site) -status ("precheck {0}/{1}: {2}" -f ([int]$phaseDone + 1), $ips.Count, $ip) -current $phaseDone -total $phaseTotal
            $precheck = Test-GeoAvailability -site $site -ip $ip -timeout $precheckTimeoutSec
            Update-ProbeStat -stat $stats[$ip] -probe $precheck
            $phaseDone++
            Show-ChildProgress -id 2 -parentId 1 -activity ("Подбор IP: {0}" -f $site) -status ("precheck готов: {0}" -f $ip) -current $phaseDone -total $phaseTotal
        }

        $shortlist = @(
            Get-ProbeRanking -stats $stats |
                Where-Object { $_.GeoBlocked -eq 0 } |
                Select-Object -First $fullProbeTopIps
        )

        if ($shortlist.Count -eq 0) {
            $shortlist = @(Get-ProbeRanking -stats $stats | Select-Object -First $fullProbeTopIps)
        }

        foreach ($entry in $shortlist) {
            $ip = [string]$entry.Ip
            if (-not $ip) { continue }
            if ($stats[$ip].GeoBlocked -gt 0) { continue }

            $ipDeadline = (Get-Date).AddSeconds($windowSec)
            do {
                $elapsedSec = [int][Math]::Max(0, ((Get-Date) - ($ipDeadline.AddSeconds(-$windowSec))).TotalSeconds)
                $partial = [Math]::Min(0.95, ($elapsedSec / [double][Math]::Max($windowSec, 1)))
                Show-ChildProgress -id 2 -parentId 1 -activity ("Подбор IP: {0}" -f $site) -status ("full-check {0} | {1}s/{2}s | попыток {3}" -f $ip, $elapsedSec, $windowSec, $stats[$ip].Attempts) -current ($phaseDone + $partial) -total $phaseTotal
                $probe = Test-GeoAvailability -site $site -ip $ip -timeout $timeout
                $stat = $stats[$ip]
                Update-ProbeStat -stat $stat -probe $probe
                $stats[$ip] = $stat

                if ($probe.GeoBlocked) { break }
                if ($stat.Attempts -ge 3 -and $stat.ReachableCount -eq $stat.Attempts) { break }
                if ($stat.Attempts -ge 2 -and $stat.ReachableCount -eq 0 -and $stat.Failed -ge 2) { break }
            } while ((Get-Date) -lt $ipDeadline)
            $phaseDone++
            Show-ChildProgress -id 2 -parentId 1 -activity ("Подбор IP: {0}" -f $site) -status ("full-check завершён: {0} | попыток {1}" -f $ip, $stats[$ip].Attempts) -current $phaseDone -total $phaseTotal
        }
    }

    $bestReachable = @(
        Get-ProbeRanking -stats $stats |
            Where-Object { $_.ReachableCount -gt 0 -and $_.GeoBlocked -eq 0 }
    ) | Select-Object -First 1

    Complete-ProgressBar -id 2 -parentId 1 -activity ("Подбор IP: {0}" -f $site)

    if (-not $bestReachable) { return $null }

    [pscustomobject]@{
        Ip = $bestReachable.Ip
        Attempts = $bestReachable.Attempts
        ReachableCount = $bestReachable.ReachableCount
        GeoBlocked = $bestReachable.GeoBlocked
        Failed = $bestReachable.Failed
        StatusCode = $bestReachable.BestCode
        BestLatency = [Math]::Round($bestReachable.BestLatency, 2)
        AvgLatency = [Math]::Round(($bestReachable.LatencySum / [Math]::Max([int]$bestReachable.Attempts, 1)), 2)
    }
}

function Test-GeoAvailability([string]$site, [string]$ip, [int]$timeout = 10) {
    $headersFile = [System.IO.Path]::GetTempFileName()
    $bodyFile = [System.IO.Path]::GetTempFileName()
    try {
        $raw = (& curl.exe -sS -k --http1.1 --compressed --range 0-24575 `
            --max-time $timeout --connect-timeout ([Math]::Min(6, $timeout)) `
            --resolve "${site}:443:${ip}" --resolve "${site}:80:${ip}" `
            -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HostParser" `
            -D $headersFile -o $bodyFile -w "%{http_code}|%{time_total}" "https://${site}" 2>$null) -replace '\s', ''

        $statusCode = 0
        $timeTotal = 999.0
        if ($raw) {
            $parts = $raw -split '\|', 2
            if ($parts.Count -ge 1) { [void][int]::TryParse($parts[0], [ref]$statusCode) }
            if ($parts.Count -eq 2) {
                [void][double]::TryParse(
                    $parts[1],
                    [System.Globalization.NumberStyles]::Float,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [ref]$timeTotal
                )
            }
        }

        $headers = if (Test-Path $headersFile) { [string](Get-Content $headersFile -Raw -ErrorAction SilentlyContinue) } else { "" }
        $body = if (Test-Path $bodyFile) { [string](Get-Content $bodyFile -Raw -ErrorAction SilentlyContinue) } else { "" }
        if (-not $headers) { $headers = "" }
        if (-not $body) { $body = "" }
        $location = ""
        $locationMatch = [regex]::Match($headers, '(?im)^Location:\s*(.+)$')
        if ($locationMatch.Success) {
            $location = $locationMatch.Groups[1].Value.Trim()
        }
        $sample = ($headers + "`n" + $body)
        if ($sample.Length -gt 32768) { $sample = $sample.Substring(0, 32768) }

        $matchedGeoPattern = $null
        foreach ($pattern in $geoBlockPatterns) {
            if ($sample -match $pattern) {
                $matchedGeoPattern = $pattern
                break
            }
        }

        $isGeoBlocked = ($statusCode -eq 451) -or [bool]$matchedGeoPattern
        $isReachable = ($statusCode -in 200, 204, 206, 301, 302, 307, 308, 401, 403, 405) -and -not $isGeoBlocked

        [pscustomobject]@{
            StatusCode = $statusCode
            TimeTotal = $timeTotal
            Reachable = $isReachable
            GeoBlocked = $isGeoBlocked
            Location = $location
            Evidence = if ($matchedGeoPattern) { $matchedGeoPattern } elseif ($statusCode -eq 451) { "http-451" } else { "" }
        }
    } finally {
        Remove-Item -LiteralPath $headersFile, $bodyFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-HostsSourceContent([string]$url, [int]$timeoutSec = 30) {
    if ($url -like "https://freedom.mafioznik.xyz/file/hosts*") {
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("hostparser_" + [System.Guid]::NewGuid().ToString("N") + ".txt")
        try {
            Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec $timeoutSec -OutFile $tempFile -ErrorAction Stop | Out-Null
            return Get-Content -Path $tempFile -Raw -Encoding UTF8
        } finally {
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
    }

    return (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec $timeoutSec -ErrorAction Stop).Content
}

$finalCheckDomains = if (Test-Path $coreFile) {
    @(Get-Content $coreFile -Encoding UTF8 | ForEach-Object { Normalize-Domain $_ } | Where-Object { $_ })
} else {
    @("openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "telegram.org", "instagram.com", "tiktok.com")
}

Write-Host ""
Write-Host "  +--------------------------------------------+" -ForegroundColor Cyan
Write-Host "  |        MULTI-DNS Hosts Parser              |" -ForegroundColor Cyan
Write-Host "  +--------------------------------------------+" -ForegroundColor Cyan
Write-Host ""

$addAdobe = Get-Answer "1. Блокировка Adobe?"
$addReMalwack = Get-Answer "2. Re-Malwack (adblock/malware)?"
$openPath = Get-Answer "3. Открыть папку после завершения?"

Write-Host ""
$domainsToProcess = New-Object System.Collections.Generic.List[string]
if (Test-Path $localFile) {
    foreach ($line in (Get-Content $localFile -Encoding UTF8)) {
        $domainsToProcess.Add($line)
    }
    $domainCount = @($domainsToProcess | ForEach-Object { Normalize-Domain $_ } | Where-Object { $_ } | Select-Object -Unique).Count
    Write-Host ("  Доменов в domainlist.txt : {0}" -f $domainCount) -ForegroundColor Cyan
    Write-Host ("  Быстрый precheck: {0}с на IP | полный check: до {1}с для top-{2}" -f $precheckTimeoutSec, $probeWindowSec, $fullProbeTopIps) -ForegroundColor DarkGray
    Write-Host ("  Лимит IP на домен: до {0} | core-check: до {1} IP" -f $maxCandidateIps, $coreRecoveryMaxIps) -ForegroundColor DarkGray
    Write-Host "  Geo-проверка: без автоматического follow redirect" -ForegroundColor DarkGray
    Write-Host ""
}

Write-Host "[1/5] Загрузка статичных hosts-источников..." -ForegroundColor Cyan
$sourceIndex = 0
foreach ($url in $staticHostsUrls) {
    $sourceIndex++
    try {
        $raw = Get-HostsSourceContent -url $url -timeoutSec 30
        $added = Import-HostsContent -content $raw -targetMap $staticIpMap
        Write-Host ("  [{0}/{1}] +{2} записей :: {3}" -f $sourceIndex, $staticHostsUrls.Count, $added, $url) -ForegroundColor Green
    } catch {
        Write-Host ("  [{0}/{1}] ! ошибка загрузки :: {2}" -f $sourceIndex, $staticHostsUrls.Count, $url) -ForegroundColor Yellow
    }
}
Write-Host ("  Уникальных доменов: {0} | Уникальных IP: {1}" -f $staticIpMap.Count, $proxyIpList.Count) -ForegroundColor DarkGray
Write-Host ""

if ($addAdobe) {
    Write-Host "[2/5] Загрузка Adobe blocklist..." -ForegroundColor Cyan
    try {
        $content = (Invoke-WebRequest -Uri $adobeUrl -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop).Content -split "`r?`n"
        foreach ($line in $content) {
            $clean = $line.Split('#')[0].Trim()
            if ($clean -match '^(?:(?:0\.0\.0\.0|127\.0\.0\.1)\s+)?([a-z0-9][a-z0-9._-]*\.[a-z]{2,})$') {
                $adobeDomain = $Matches[1].ToLower()
                $adobeDomains[$adobeDomain] = $true
            }
        }
        Write-Host ("  Доменов Adobe: {0}" -f $adobeDomains.Count) -ForegroundColor Green
    } catch {
        Write-Host "  Пропуск Adobe blocklist: ошибка сети" -ForegroundColor Yellow
    }
    Write-Host ""
}

if ($addReMalwack) {
    Write-Host "[3/5] Загрузка Re-Malwack blocklist..." -ForegroundColor Cyan
    try {
        $raw = (Invoke-WebRequest -Uri $reMalwackUrl -UseBasicParsing -TimeoutSec 45 -ErrorAction Stop).Content
        [void](Import-HostsContent -content $raw -targetMap $reMalwackDomains -IncludeBlockingTargets)
        Write-Host ("  Доменов Re-Malwack: {0}" -f $reMalwackDomains.Count) -ForegroundColor Green
    } catch {
        Write-Host "  Пропуск Re-Malwack: ошибка сети" -ForegroundColor Yellow
    }
    Write-Host ""
}

$processingEstimate = Get-ProcessingEstimate `
    -rawDomains @($domainsToProcess) `
    -coreDomains $finalCheckDomains `
    -includeAdobe $addAdobe `
    -includeReMalwack $addReMalwack

Write-Host "[4/5] Подбор лучшей связки IP + домен..." -ForegroundColor Cyan
Write-Host ("  Оценка: около {0} | потолок до {1}" -f (Format-Duration $processingEstimate.TotalRoughSec), (Format-Duration $processingEstimate.TotalMaxSec)) -ForegroundColor DarkGray
Write-Host ("  Основной подбор: single {0} | multi {1} | без IP {2} | IP-кандидатов {3}" -f $processingEstimate.SingleCandidateDomains, $processingEstimate.MultiCandidateDomains, $processingEstimate.NoCandidateDomains, $processingEstimate.TotalCandidateIps) -ForegroundColor DarkGray
Write-Host ("  Финальный core-check: доменов {0} | ориентир {1} | потолок до {2}" -f $processingEstimate.CoreDomainCount, (Format-Duration $processingEstimate.CoreRoughSec), (Format-Duration $processingEstimate.CoreMaxSec)) -ForegroundColor DarkGray

$resolvedStatic = 0
$resolvedInherited = 0
$blockedAdobe = 0
$blockedReMalwack = 0
$staticOrderFallback = 0
$unresolved = 0
$processedCount = 0
$stage4Total = [Math]::Max($processingEstimate.UniqueDomainCount, 1)

foreach ($rawDomain in $domainsToProcess) {
    $domain = Normalize-Domain $rawDomain
    if (-not $domain) { continue }
    if (-not $seenDomains.Add($domain)) { continue }

    Show-StageProgress -id 1 -activity "[4/5] Подбор лучшей связки IP + домен" -status ("{0}/{1} :: {2}" -f ($processedCount + 1), $stage4Total, $domain) -current $processedCount -total $stage4Total
    $processedCount++

    if ($addAdobe -and $adobeDomains.ContainsKey($domain)) {
        $processedDomains[$domain] = "127.0.0.1"
        $blockedAdobe++
        continue
    }

    if ($addReMalwack -and $reMalwackDomains.ContainsKey($domain)) {
        $processedDomains[$domain] = "0.0.0.0"
        $blockedReMalwack++
        continue
    }

    $candidates = Get-CandidateIps -domain $domain -map $staticIpMap -limit $maxCandidateIps
    $best = $null
    if ($candidates.Count -gt 0) {
        $best = Find-BestCandidate -site $domain -candidateIps $candidates -windowSec $probeWindowSec -timeout $probeTimeoutSec
    }

    if ($best) {
        $processedDomains[$domain] = $best.Ip
        $resolvedStatic++
        $statusLabel = if ($best.Attempts -gt 1) { "POOL" } else { "STATIC" }
        Write-Host ("  [{0}] {1} -> {2} (доступ {3}/{4}, geo {5}, avg {6}s)" -f $statusLabel, $domain, $best.Ip, $best.ReachableCount, $best.Attempts, $best.GeoBlocked, $best.AvgLatency) -ForegroundColor Green
        continue
    }

    $inheritedIp = Get-InheritedResolvedIp -domain $domain -map $processedDomains
    if ($inheritedIp) {
        $inheritCheck = Test-GeoAvailability -site $domain -ip $inheritedIp -timeout $inheritedProbeTimeoutSec
        if ($inheritCheck.Reachable) {
            $processedDomains[$domain] = $inheritedIp
            $resolvedInherited++
            Write-Host ("  [INHERITED] {0} -> {1} (доступ 1/1, geo 0, avg {2}s)" -f $domain, $inheritedIp, ([Math]::Round($inheritCheck.TimeTotal, 2))) -ForegroundColor Magenta
            continue
        }
    }

    if ($staticIpMap.ContainsKey($domain) -and $staticIpMap[$domain].Count -gt 0) {
        $staticOrderFallback++
        $firstStaticIp = [string]$staticIpMap[$domain][0]
        $reserveCount = [Math]::Max(0, $staticIpMap[$domain].Count - 1)
        Write-Host ("  [STATIC-ORDER] {0} -> {1} (+{2} reserve)" -f $domain, $firstStaticIp, $reserveCount) -ForegroundColor DarkCyan
        continue
    }

    $unresolved++
    if (($processedCount % 100) -eq 0) {
        Write-Host ("  ... обработано {0}, без IP пока {1}" -f $processedCount, $unresolved) -ForegroundColor DarkGray
    }
}
Complete-ProgressBar -id 2 -parentId 1 -activity "Подбор IP"
Complete-ProgressBar -id 1 -activity "[4/5] Подбор лучшей связки IP + домен"
Write-Host ("  Итог: POOL {0} | STATIC-ORDER {1} | INHERITED {2} | Adobe {3} | Re-Malwack {4} | No static {5}" -f $resolvedStatic, $staticOrderFallback, $resolvedInherited, $blockedAdobe, $blockedReMalwack, $unresolved) -ForegroundColor Cyan
Write-Host ""

Write-Host "[5/5] Финальная проверка core-доменов + geo-block..." -ForegroundColor Cyan
$coreOk = 0
$geoFixed = 0
$coreAdded = 0
$coreFailed = 0
$coreProcessed = 0
$successfulIpCounts = @{}
foreach ($value in $processedDomains.Values) {
    $resolvedIp = [string]$value
    if ($resolvedIp -match '^\d{1,3}(?:\.\d{1,3}){3}$' -and $resolvedIp -notmatch '^(0\.0\.0\.0|127\.)') {
        if (-not $successfulIpCounts.ContainsKey($resolvedIp)) { $successfulIpCounts[$resolvedIp] = 0 }
        $successfulIpCounts[$resolvedIp]++
    }
}
$preferredRecoveryIps = @(
    $successfulIpCounts.GetEnumerator() |
        Sort-Object `
            @{ Expression = { [int]$_.Value }; Descending = $true },
            @{ Expression = { [string]$_.Key }; Descending = $false } |
        ForEach-Object { [string]$_.Key }
)

foreach ($siteRaw in $finalCheckDomains) {
    $site = Normalize-Domain $siteRaw
    if (-not $site) { continue }

    $coreProcessed++
    Show-StageProgress -id 1 -activity "[5/5] Финальная проверка core-доменов + geo-block" -status ("{0}/{1} :: {2}" -f $coreProcessed, [Math]::Max($processingEstimate.CoreDomainCount, 1), $site) -current ($coreProcessed - 1) -total ([Math]::Max($processingEstimate.CoreDomainCount, 1))

    $currentIp = $null
    if ($processedDomains.ContainsKey($site)) {
        $currentIp = [string]$processedDomains[$site]
    }

    $validated = $false
    if ($currentIp -and $currentIp -match '^\d{1,3}(?:\.\d{1,3}){3}$') {
        $currentCheck = Test-GeoAvailability -site $site -ip $currentIp -timeout $geoProbeTimeoutSec
        if ($currentCheck.Reachable) {
            $coreOk++
            $validated = $true
            Write-Host ("  [OK] {0} -> {1} (HTTP {2})" -f $site, $currentIp, $currentCheck.StatusCode) -ForegroundColor Green
        } else {
            $reason = Get-ProbeReason -probe $currentCheck
            Write-Host ("  [RECHECK] {0} -> {1} ({2})" -f $site, $currentIp, $reason) -ForegroundColor Yellow
        }
    }

    if ($validated) { continue }

    $recoveryIps = @(Get-PreferredRecoveryIps -site $site -currentIp $currentIp -preferredIps $preferredRecoveryIps -limit $coreRecoveryMaxIps)
    $recoveryIndex = 0
    foreach ($proxyIp in $recoveryIps) {
        $recoveryIndex++
        Show-ChildProgress -id 2 -parentId 1 -activity ("Core-check: {0}" -f $site) -status ("IP {0}/{1}: {2}" -f $recoveryIndex, [Math]::Max($recoveryIps.Count, 1), $proxyIp) -current ($recoveryIndex - 1) -total ([Math]::Max($recoveryIps.Count, 1))

        $probe = Test-GeoAvailability -site $site -ip $proxyIp -timeout $geoProbeTimeoutSec
        if ($probe.Reachable) {
            $processedDomains[$site] = $proxyIp
            $coreOk++
            if ($currentIp) {
                $geoFixed++
                Write-Host ("  [GEO-FIX] {0} -> {1} (HTTP {2})" -f $site, $proxyIp, $probe.StatusCode) -ForegroundColor Cyan
            } else {
                $coreAdded++
                Write-Host ("  [RECOVERED] {0} -> {1} (HTTP {2})" -f $site, $proxyIp, $probe.StatusCode) -ForegroundColor Cyan
            }
            $validated = $true
            break
        }
    }
    Complete-ProgressBar -id 2 -parentId 1 -activity ("Core-check: {0}" -f $site)

    if (-not $validated) {
        $coreFailed++
        Write-Host ("  [MISS] {0}" -f $site) -ForegroundColor DarkYellow
    }
}
Complete-ProgressBar -id 1 -activity "[5/5] Финальная проверка core-доменов + geo-block"
Write-Host ("  Core OK: {0} | Geo fixed: {1} | Added missing: {2} | Failed: {3}" -f $coreOk, $geoFixed, $coreAdded, $coreFailed) -ForegroundColor Cyan
Write-Host ""

Write-Host "[OUTPUT] Генерация hosts_merged.txt..." -ForegroundColor Cyan
$outLines = New-Object System.Collections.Generic.List[string]
$outLines.Add("# Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$outLines.Add("# Mode      : GeoHideDNS-first merge + precheck + geo recheck (no auto-redirect)")
$outLines.Add("# Sources   : $($staticHostsUrls.Count) static, Adobe=$addAdobe, ReMalwack=$addReMalwack")
$outLines.Add("# Static    : exact static entries preserved; runtime test only reorders/prioritizes")
$outLines.Add("# ================================================================")
$outLines.Add("")

$exactStaticWritten = 0
$exactDomainsImproved = 0
$exactDomainsStaticOrder = 0
$inheritedWritten = 0
$runtimeOnlyWritten = 0

if (Test-Path $localFile) {
    foreach ($line in (Get-Content $localFile -Encoding UTF8)) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            $outLines.Add("")
            continue
        }
        if ($trimmed.StartsWith('#')) {
            $outLines.Add($trimmed)
            continue
        }

        $domain = Normalize-Domain $trimmed
        if (-not $domain) { continue }
        if (-not $writtenDomains.Add($domain)) { continue }

        if ($addAdobe -and $adobeDomains.ContainsKey($domain)) { continue }
        if ($addReMalwack -and $reMalwackDomains.ContainsKey($domain)) { continue }

        $orderedIps = @(Get-OrderedOutputIps -domain $domain -staticMap $staticIpMap -runtimeMap $processedDomains)
        $hasExactStatic = $staticIpMap.ContainsKey($domain) -and $staticIpMap[$domain].Count -gt 0

        if ($hasExactStatic) {
            if ($orderedIps.Count -eq 0) { continue }

            foreach ($ip in $orderedIps) {
                $outLines.Add($ip.PadRight(20) + $domain)
            }

            $exactStaticWritten++
            $runtimeIp = if ($processedDomains.ContainsKey($domain)) { [string]$processedDomains[$domain] } else { $null }
            $firstStaticIp = [string]$staticIpMap[$domain][0]
            if ((Is-OutputtableIp $runtimeIp) -and (($runtimeIp -ne $firstStaticIp) -or ($staticIpMap[$domain].Count -gt 1))) {
                $exactDomainsImproved++
            } else {
                $exactDomainsStaticOrder++
            }
            continue
        }

        if ($orderedIps.Count -gt 0) {
            foreach ($ip in $orderedIps) {
                $outLines.Add($ip.PadRight(20) + $domain)
            }
            $inheritedWritten++
        }
    }
}

$recoveredInOutput = 0
$pendingCoreDomains = @($finalCheckDomains | ForEach-Object { Normalize-Domain $_ } | Where-Object { $_ })
if ($pendingCoreDomains.Count -gt 0) {
    $outLines.Add("")
    $outLines.Add("# --- Final Access Recovery ---")
    foreach ($domain in $pendingCoreDomains) {
        if (-not $processedDomains.ContainsKey($domain)) { continue }
        if (-not $writtenDomains.Add($domain)) { continue }

        $ip = [string]$processedDomains[$domain]
        if (Is-OutputtableIp $ip) {
            $outLines.Add($ip.PadRight(20) + $domain)
            $recoveredInOutput++
            $runtimeOnlyWritten++
        }
    }
}

$adobeAdded = 0
if ($addAdobe -and $adobeDomains.Count -gt 0) {
    $outLines.Add("")
    $outLines.Add("# --- Adobe Blocklist ---")
    foreach ($domain in $adobeDomains.Keys) {
        if (-not $writtenDomains.Add($domain)) { continue }
        $outLines.Add("127.0.0.1".PadRight(20) + $domain)
        $adobeAdded++
    }
}

$reMalwackAdded = 0
if ($addReMalwack -and $reMalwackDomains.Count -gt 0) {
    $outLines.Add("")
    $outLines.Add("# --- Re-Malwack Blocklist ---")
    foreach ($domain in $reMalwackDomains.Keys) {
        if (-not $writtenDomains.Add($domain)) { continue }
        $outLines.Add("0.0.0.0".PadRight(20) + $domain)
        $reMalwackAdded++
    }
}

$outLines | Out-File $mergedFile -Encoding UTF8 -Force

$elapsed = (Get-Date) - $scriptStart
$finalCount = ($outLines | Where-Object { $_ -match '^\d{1,3}\.' }).Count
Write-Host ("  Фактическое время работы: {0}" -f (Format-Duration ([int]$elapsed.TotalSeconds))) -ForegroundColor DarkGray
Write-Host ("  Output: exact {0} | improved {1} | static-order {2} | inherited {3} | recovered {4}" -f $exactStaticWritten, $exactDomainsImproved, $exactDomainsStaticOrder, $inheritedWritten, $runtimeOnlyWritten) -ForegroundColor DarkGray
Write-Host ("  Готово за {0} | Записей: {1} | Core recovery: {2} | Adobe: {3} | Re-Malwack: {4}" -f (Format-Duration ([int]$elapsed.TotalSeconds)), $finalCount, $recoveredInOutput, $adobeAdded, $reMalwackAdded) -ForegroundColor Yellow

if ($openPath -and (Test-Path $mergedFile)) {
    & explorer.exe /select,"$mergedFile"
}

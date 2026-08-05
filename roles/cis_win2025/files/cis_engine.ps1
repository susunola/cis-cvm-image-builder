<#
.SYNOPSIS
CIS Windows Server Benchmark — assessment engine.
Driven by rules.json catalog, outputs result.json.

.PARAMETER Catalog
Path to rules.json
.PARAMETER Mode
scan | apply
.PARAMETER Profile
L1 | L2
.PARAMETER Out
Output JSON path (default: result.json)
#>

param(
    [string]$Catalog = "rules.json",
    [string]$Mode = "scan",
    [string]$Profile = "L1",
    [string]$Platform = "server",
    [string]$Out = "result.json",
    [string]$Include = "",
    [string]$Exclude = "",
    [string]$Sections = "",
    [string]$Families = "",
    [string]$BackupDir = "",
    [switch]$AllowDisruptive
)

$ErrorActionPreference = "Stop"
$startedAt = (Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz")
$sw = [System.Diagnostics.Stopwatch]::StartNew()

# ── Helpers ────────────────────────────────────────────────
function Write-Result {
    param($Id, $Title, $Section, $Status, $Level, $Assessment = "Automated",
          $Family = "", $Risk = "safe", $Detail = "", $Page = 0, $Levels = @())
    $global:Results += [PSCustomObject]@{
        id = $Id; title = $Title; section = $Section; status = $Status
        level = $Level; assessment = $Assessment; family = $Family
        risk = $Risk; detail = $Detail; page = $Page; levels = $Levels
        duration_ms = 0; apply_status = "n/a"
    }
}

function Get-SecPol {
    param($Area, $Key)
    $tmp = $null
    try {
        $tmp = "$env:TEMP\secpol_$([Guid]::NewGuid()).inf"
        secedit /export /cfg $tmp /areas $Area 2>$null | Out-Null
        if (Test-Path $tmp) {
            $content = Get-Content $tmp -Raw
            if ($content -match "(?m)^\s*$Key\s*=\s*(.+)$") {
                return $Matches[1].Trim()
            }
        }
    } catch {}
    finally {
        if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
    return $null
}

# ── Checks ─────────────────────────────────────────────────
function Invoke-Check {
    param($Rule, $Ctx)

    $id = $Rule.id
    $family = $Rule.family
    $params = $Rule.params

    switch ($family) {

        # ── 1. Account Policies ──
        "password-policy" {
            $key = $params.key
            $expected = $params.expected
            $val = Get-SecPol "SECURITYPOLICY" $key
            if ($null -ne $val) {
                $ok = ([int]$val -ge [int]$expected) -or ($params.op -eq "eq" -and $val -eq $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="$key=$val (expected ≥$expected)"}
            }
            return @{status="error"; detail="$key not found in security policy"}
        }

        "password-complexity" {
            $val = Get-SecPol "SECURITYPOLICY" "PasswordComplexity"
            $ok = ($val -eq "1")
            return @{status=if($ok){"pass"}else{"fail"}; detail="PasswordComplexity=$val"}
        }

        "password-reversible" {
            $val = Get-SecPol "SECURITYPOLICY" "ClearTextPassword"
            $ok = ($val -eq "0")
            return @{status=if($ok){"pass"}else{"fail"}; detail="ClearTextPassword=$val"}
        }

        # ── 2. Account Lockout ──
        "lockout-policy" {
            $key = $params.key
            $expected = $params.expected
            $op = if ($params.op) { $params.op } else { "le" }
            $val = Get-SecPol "SECURITYPOLICY" $key
            if ($null -ne $val) {
                if ($op -eq "le") { $ok = [int]$val -le [int]$expected }
                elseif ($op -eq "ge") { $ok = [int]$val -ge [int]$expected }
                else { $ok = ($val -eq $expected) }
                return @{status=if($ok){"pass"}else{"fail"}; detail="$key=$val (expected $op $expected)"}
            }
            return @{status="error"; detail="$key not found"}
        }

        # ── 3. Audit Policy ──
        "audit-policy" {
            $subcategory = $params.subcategory
            $expected = $params.expected
            try {
                $out = auditpol /get /subcategory:"$subcategory" 2>&1 | Out-String
                if ($out -match "$subcategory\s+(.+)$") {
                    $actual = $Matches[1].Trim()
                    $ok = ($actual -eq $expected)
                    return @{status=if($ok){"pass"}else{"fail"}; detail="$subcategory = $actual (expected $expected)"}
                }
            } catch {}
            return @{status="error"; detail="Failed to query audit policy: $subcategory"}
        }

        # ── 4. User Rights Assignment ──
        "user-right" {
            $privilege = $params.privilege
            $expectedSid = $params.expected_sid
            $tmp = $null
            try {
                $tmp = "$env:TEMP\ur_$([Guid]::NewGuid()).inf"
                secedit /export /cfg $tmp /areas USER_RIGHTS 2>$null | Out-Null
                if (Test-Path $tmp) {
                    $content = Get-Content $tmp -Raw
                    if ($content -match "(?m)^\s*$privilege\s*=\s*(.+)$") {
                        $sids = $Matches[1].Trim() -split ','
                        $ok = ($sids | Where-Object { $_.Trim() -eq $expectedSid })
                        return @{status=if($ok){"pass"}else{"fail"}; detail="$privilege members: $($Matches[1].Trim())"}
                    }
                }
            } catch {}
            finally {
                if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
            }
            return @{status="error"; detail="Failed to query $privilege"}
        }

        # ── 5. Security Options (Registry) ──
        "reg-dword" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ($val -eq $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="$path\$name = $val (expected $expected)"}
            } catch { return @{status="error"; detail="Registry key not found: $path\$name"} }
        }

        "reg-string" {
            $path = $params.path
            $name = $params.name
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ($val -eq $params.value)
                return @{status=if($ok){"pass"}else{"fail"}; detail="$path\$name = '$val' (expected '$($params.value)')"}
            } catch { return @{status="error"; detail="Registry key not found: $path\$name"} }
        }

        "reg-exists" {
            $path = $params.path
            $ok = Test-Path $path
            return @{status=if($ok){"pass"}else{"fail"}; detail="$path exists=$ok"}
        }

        # ── 6. Windows Firewall ──
        "firewall-profile" {
            $profile = $params.profile
            try {
                $fw = Get-NetFirewallProfile -Name $profile -ErrorAction Stop
                $enabled = $fw.Enabled
                $defaultIn = $fw.DefaultInboundAction
                $defaultOut = $fw.DefaultOutboundAction
                $ok = ($enabled -eq "True" -and $defaultIn -eq "Block" -and $defaultOut -eq "Allow")
                return @{
                    status = if($ok){"pass"}else{"fail"}
                    detail = "${profile}: enabled=$enabled inbound=$defaultIn outbound=$defaultOut"
                }
            } catch {
                return @{status="error"; detail="Failed to query firewall profile $profile"}
            }
        }

        # ── 7. Service Configuration ──
        "service-state" {
            $name = $params.name
            $expected = $params.state
            try {
                $svc = Get-Service -Name $name -ErrorAction Stop
                $ok = ($svc.Status -eq $expected -or $svc.StartType -eq $expected)
                return @{
                    status = if($ok){"pass"}else{"fail"}
                    detail = "${name}: status=$($svc.Status) startType=$($svc.StartType) (expected $expected)"
                }
            } catch {
                if ($expected -eq "NotFound") {
                    return @{status="pass"; detail="${name}: not installed (expected)"}
                }
                return @{status="fail"; detail="${name}: not found (expected $expected)"}
            }
        }

        # ── 8. Windows Update ──
        "wu-config" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ($val -eq $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="WindowsUpdate\$name = $val (expected $expected)"}
            } catch { return @{status="error"; detail="WU key not found"} }
        }

        # ── 9. UAC ──
        "uac" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ($val -eq $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="UAC\$name = $val (expected $expected)"}
            } catch { return @{status="error"; detail="UAC key not found"} }
        }

        # ── 10. Network Security ──
        "lanman-auth" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ([int]$val -ge [int]$expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="LmCompatibilityLevel = $val (expected ≥$expected)"}
            } catch { return @{status="error"; detail="LSA key not found"} }
        }

        "smb-signing" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ($val -eq $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="SMB\$name = $val (expected $expected)"}
            } catch { return @{status="error"; detail="SMB key not found"} }
        }

        # ── 11. RDP Security ──
        "rdp-nla" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ($val -eq $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="RDP NLA = $val (expected $expected)"}
            } catch { return @{status="error"; detail="RDP key not found"} }
        }

        # ── 12. Event Log ──
        "eventlog-size" {
            $logName = $params.log
            $expectedMB = $params.min_size_mb
            try {
                $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
                $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 0)
                $ok = ($sizeMB -ge $expectedMB)
                return @{status=if($ok){"pass"}else{"fail"}; detail="$logName max=$sizeMB MB (expected ≥$expectedMB MB)"}
            } catch { return @{status="error"; detail="Event log $logName not found"} }
        }

        # ── 13. PowerShell Security ──
        "ps-execution" {
            try {
                $policy = Get-ExecutionPolicy -Scope LocalMachine
                $ok = ($policy -eq "RemoteSigned" -or $policy -eq "Restricted" -or $policy -eq "AllSigned")
                return @{status=if($ok){"pass"}else{"fail"}; detail="ExecutionPolicy=$policy"}
            } catch { return @{status="error"; detail="Failed to query execution policy"} }
        }

        "ps-logging" {
            $path = $params.path
            $name = $params.name
            $expected = $params.value
            try {
                if (Test-Path $path) {
                    $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                    $ok = ($val -eq $expected)
                    return @{status=if($ok){"pass"}else{"fail"}; detail="PS logging $name=$val"}
                }
            } catch {}
            return @{status="fail"; detail="PS logging key not found"}
        }

        default {
            return @{status="error"; detail="Unknown family: $family"}
        }
    }
}

# ── Apply (Remediation) ─────────────────────────────────────
function Invoke-Fix {
    param($Rule)

    $family = $Rule.family
    $params = $Rule.params

    switch ($family) {

        "password-policy" {
            $key = $params.key; $expected = $params.expected
            $val = Get-SecPol "SECURITYPOLICY" $key
            if ($null -eq $val) { return "error: cannot read $key" }
            $isOk = if ($params.op -eq "ge") { [int]$val -ge [int]$expected }
                    elseif ($params.op -eq "le") { [int]$val -le [int]$expected }
                    else { $val -eq $expected }
            if ($isOk) { return "already" }
            try {
                $tmpInf = "$env:TEMP\secpol_fix_$([Guid]::NewGuid()).inf"
                secedit /export /cfg $tmpInf /areas SECURITYPOLICY 2>$null | Out-Null
                $c = Get-Content $tmpInf -Raw
                if ($c -match "(?m)^(\s*[^\s=]*\s*=\s*).+$") {
                    if ($c -match "(?m)^(\s*$key\s*=\s*).+$") {
                        $c = $c -replace "(?m)^(\s*$key\s*=\s*).+$", "`${1}$expected"
                    } else {
                        $c += "`r`n$key = $expected"
                    }
                    [System.IO.File]::WriteAllText($tmpInf, $c)
                    secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $tmpInf /areas SECURITYPOLICY 2>$null | Out-Null
                }
                Remove-Item $tmpInf -Force -ErrorAction SilentlyContinue
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "lockout-policy" {
            $key = $params.key; $expected = $params.expected
            $op = if ($params.op) { $params.op } else { "le" }
            $val = Get-SecPol "SECURITYPOLICY" $key
            if ($null -eq $val) { return "error: cannot read $key" }
            $isOk = if ($op -eq "le") { [int]$val -le [int]$expected }
                    elseif ($op -eq "ge") { [int]$val -ge [int]$expected }
                    else { $val -eq $expected }
            if ($isOk) { return "already" }
            try {
                $tmpInf = "$env:TEMP\secpol_fix_$([Guid]::NewGuid()).inf"
                secedit /export /cfg $tmpInf /areas SECURITYPOLICY 2>$null | Out-Null
                $c = Get-Content $tmpInf -Raw
                if ($c -match "(?m)^(\s*$key\s*=\s*).+$") {
                    $c = $c -replace "(?m)^(\s*$key\s*=\s*).+$", "`${1}$expected"
                } else {
                    $c += "`r`n$key = $expected"
                }
                [System.IO.File]::WriteAllText($tmpInf, $c)
                secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $tmpInf /areas SECURITYPOLICY 2>$null | Out-Null
                Remove-Item $tmpInf -Force -ErrorAction SilentlyContinue
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "audit-policy" {
            $subcategory = $params.subcategory; $expected = $params.expected
            try {
                $out = auditpol /get /subcategory:"$subcategory" 2>&1 | Out-String
                if ($out -match "$subcategory\s+(.+)$") {
                    if ($Matches[1].Trim() -eq $expected) { return "already" }
                }
                auditpol /set /subcategory:"$subcategory" /success:enable /failure:enable 2>$null | Out-Null
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "user-right" {
            $privilege = $params.privilege; $expectedSid = $params.expected_sid
            if (-not $expectedSid) { return "skipped: no expected SID defined" }
            try {
                $tmp = "$env:TEMP\ur_$([Guid]::NewGuid()).inf"
                secedit /export /cfg $tmp /areas USER_RIGHTS 2>$null | Out-Null
                if (Test-Path $tmp) {
                    $c = Get-Content $tmp -Raw
                    if ($c -match "(?m)^\s*$([regex]::Escape($privilege))\s*=\s*(.+)$") {
                        if ($Matches[1] -match [regex]::Escape($expectedSid)) { Remove-Item $tmp -Force; return "already" }
                    }
                }
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
                $tmp2 = "$env:TEMP\ur_fix_$([Guid]::NewGuid()).inf"
                secedit /export /cfg $tmp2 /areas USER_RIGHTS 2>$null | Out-Null
                $c = Get-Content $tmp2 -Raw
                if ($c -match "(?m)^(\s*$([regex]::Escape($privilege))\s*=\s*).+$") {
                    $c = $c -replace "(?m)^(\s*$([regex]::Escape($privilege))\s*=\s*).+$", "`${1}$expectedSid"
                } else {
                    $c += "`r`n$privilege = $expectedSid"
                }
                [System.IO.File]::WriteAllText($tmp2, $c)
                secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $tmp2 /areas USER_RIGHTS 2>$null | Out-Null
                Remove-Item $tmp2 -Force -ErrorAction SilentlyContinue
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "reg-dword" {
            $path = $params.path; $name = $params.name; $expected = $params.value
            try {
                $current = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                if ($current -eq $expected) { return "already" }
            } catch {}
            try {
                if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                Set-ItemProperty -Path $path -Name $name -Value $expected -Type DWord -Force
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "firewall-profile" {
            $profile = $params.profile
            try {
                $fw = Get-NetFirewallProfile -Name $profile -ErrorAction Stop
                if ($fw.Enabled -eq "True" -and $fw.DefaultInboundAction -eq "Block") { return "already" }
                Set-NetFirewallProfile -Name $profile -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "service-state" {
            $name = $params.name; $expected = $params.state
            try {
                $svc = Get-Service -Name $name -ErrorAction Stop
                if ($expected -eq "Stopped" -and $svc.Status -eq "Stopped") { return "already" }
                if ($expected -eq "Running" -and $svc.Status -eq "Running") { return "already" }
                if ($expected -eq "Stopped") {
                    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $name -StartupType Disabled
                } elseif ($expected -eq "Running") {
                    Set-Service -Name $name -StartupType Automatic
                    Start-Service -Name $name -ErrorAction SilentlyContinue
                } elseif ($expected -eq "Auto") {
                    Set-Service -Name $name -StartupType Automatic
                }
                return "applied"
            } catch {
                if ($expected -eq "NotFound") { return "already" }
                return "failed: $($_.Exception.Message)"
            }
        }

        "smb-signing" {
            $path = $params.path; $name = $params.name; $expected = $params.value
            try {
                $current = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                if ($current -eq $expected) { return "already" }
            } catch {}
            try {
                if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                Set-ItemProperty -Path $path -Name $name -Value $expected -Type DWord -Force
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "rdp-nla" {
            $path = $params.path; $name = $params.name; $expected = $params.value
            try {
                $current = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                if ($current -eq $expected) { return "already" }
            } catch {}
            try {
                if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                Set-ItemProperty -Path $path -Name $name -Value $expected -Type DWord -Force
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "eventlog-size" {
            $logName = $params.log; $expectedMB = $params.min_size_mb
            try {
                $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
                $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 0)
                if ($sizeMB -ge $expectedMB) { return "already" }
                $log.MaximumSizeInBytes = $expectedMB * 1MB
                $log.SaveChanges()
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "ps-execution" {
            try {
                $policy = Get-ExecutionPolicy -Scope LocalMachine
                if ($policy -eq "RemoteSigned" -or $policy -eq "Restricted" -or $policy -eq "AllSigned") {
                    return "already"
                }
                Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "ps-logging" {
            $path = $params.path; $name = $params.name; $expected = $params.value
            try {
                if (Test-Path $path) {
                    $current = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                    if ($current -eq $expected) { return "already" }
                }
            } catch {}
            try {
                if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
                Set-ItemProperty -Path $path -Name $name -Value $expected -Type DWord -Force
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        default { return "skipped: no fix for family $family" }
    }
}

# ── Load Rules ──────────────────────────────────────────────
try {
    $raw = [System.IO.File]::ReadAllText($Catalog)
    $catalog = $raw | ConvertFrom-Json
    if (-not $catalog -or $catalog.Count -eq 0) {
        Write-Error "Catalog is empty or failed to parse: $Catalog"
        exit 1
    }
} catch {
    Write-Error "Failed to load rules catalog: $_"
    exit 1
}

$includeList = if ($Include) { $Include -split ',' | % { $_.Trim() } } else { @() }
$excludeList = if ($Exclude) { $Exclude -split ',' | % { $_.Trim() } } else { @() }
$sectionList = if ($Sections) { $Sections -split ',' | % { $_.Trim() } } else { @() }
$familyList  = if ($Families)  { $Families  -split ',' | % { $_.Trim() } } else { @() }

# Filter rules
$rules = @()
foreach ($r in $catalog) {
    # Level filter
    if ($Profile -eq "L1" -and $r.levels -notcontains 1) { continue }
    # Platform filter
    if ($Platform -and $r.platforms -and $r.platforms -notcontains $Platform) { continue }
    # Exclude — must check BEFORE adding to $rules
    $excluded = $false
    foreach ($p in $excludeList) { if ($r.id.StartsWith($p)) { $excluded = $true; break } }
    if ($excluded) { continue }
    # Include
    if ($includeList.Count -gt 0) {
        $match = $false
        foreach ($p in $includeList) { if ($r.id.StartsWith($p)) { $match = $true; break } }
        if (-not $match) { continue }
    }
    # Section filter
    if ($sectionList.Count -gt 0) {
        $match = $false
        foreach ($s in $sectionList) { if ($r.id.StartsWith($s)) { $match = $true; break } }
        if (-not $match) { continue }
    }
    # Families filter
    if ($familyList.Count -gt 0 -and $r.family) {
        $match = $false
        foreach ($f in $familyList) { if ($r.family -eq $f) { $match = $true; break } }
        if (-not $match) { continue }
    }
    $rules += $r
}

# ── Execute ─────────────────────────────────────────────────
$global:Results = @()
$global:Changed = @()
$count = 0
$total = $rules.Count
$isApply = ($Mode -eq "apply")

if ($isApply) {
    Write-Host "CIS apply mode: will remediate failed rules"
    if (-not $AllowDisruptive) {
        Write-Host "  Disruptive rules will be skipped (use -AllowDisruptive to include)"
    }
}

foreach ($rule in $rules) {
    $count++
    $activity = if ($isApply) { "CIS Apply" } else { "CIS Scan" }
    Write-Progress -Activity $activity -Status "$($rule.id): $($rule.title)" -PercentComplete (($count / $total) * 100)
    $rsw = [System.Diagnostics.Stopwatch]::StartNew()

    # Step 1: Always run the check
    try {
        $result = Invoke-Check -Rule $rule
    } catch {
        $rsw.Stop()
        Write-Result -Id $rule.id -Title $rule.title -Section $rule.section `
            -Status "error" -Level ($rule.levels | Select-Object -First 1) `
            -Assessment $rule.assessment -Family $rule.family `
            -Risk $rule.risk -Detail "Engine error: $_" -Page $rule.page `
            -Levels @($rule.levels)
        $global:Results[-1].duration_ms = $rsw.ElapsedMilliseconds
        continue
    }

    # Step 2: If apply mode and check failed (status=fail), try to fix
    $applyStatus = "n/a"
    if ($isApply -and $result.status -eq "fail") {
        # Skip disruptive rules unless explicitly allowed
        if ($rule.risk -eq "disruptive" -and -not $AllowDisruptive) {
            $applyStatus = "skipped_disruptive"
        } else {
            try {
                $applyStatus = Invoke-Fix -Rule $rule
                if ($applyStatus -eq "applied") {
                    $global:Changed += "$($rule.id): $($rule.title)"
                }
            } catch {
                $applyStatus = "failed: $($_.Exception.Message)"
            }
        }
    } elseif ($isApply -and $result.status -ne "fail") {
        $applyStatus = "already"
    }

    $rsw.Stop()
    Write-Result -Id $rule.id -Title $rule.title -Section $rule.section `
        -Status $result.status -Level ($rule.levels | Select-Object -First 1) `
        -Assessment $rule.assessment -Family $rule.family `
        -Risk $rule.risk -Detail $result.detail -Page $rule.page `
        -Levels @($rule.levels)
    $global:Results[-1].duration_ms = $rsw.ElapsedMilliseconds
    $global:Results[-1].apply_status = $applyStatus
}

# ── Summary ─────────────────────────────────────────────────
function Get-Summary($levelFilter) {
    $filtered = if ($levelFilter) { $global:Results | Where-Object { $_.level -eq $levelFilter } } else { $global:Results }
    $pass = ($filtered | Where-Object { $_.status -eq "pass" }).Count
    $fail = ($filtered | Where-Object { $_.status -eq "fail" }).Count
    $manual = ($filtered | Where-Object { $_.status -eq "manual" }).Count
    $error = ($filtered | Where-Object { $_.status -eq "error" }).Count
    $na = ($filtered | Where-Object { $_.status -eq "notapplicable" }).Count
    $total = $filtered.Count
    $assessed = $pass + $fail
    $score = if ($assessed -gt 0) { [math]::Round(100.0 * $pass / $assessed, 1) } else { 0.0 }

    # Apply stats
    $applied = ($filtered | Where-Object { $_.apply_status -eq "applied" }).Count
    $applyFailed = ($filtered | Where-Object { $_.apply_status -match "^failed" }).Count
    $skippedRisk = ($filtered | Where-Object { $_.apply_status -eq "skipped_disruptive" }).Count
    $already = ($filtered | Where-Object { $_.apply_status -eq "already" }).Count
    $appliedPending = 0  # Windows changes take effect immediately (no reboot needed for most)

    return @{
        total = $total; pass = $pass; fail = $fail; manual = $manual; error = $error
        notapplicable = $na; skipped_by_selection = 0; assessed = $assessed
        applied = $applied; applied_pending = $appliedPending; score = $score
        apply_failed = $applyFailed; skipped_disruptive = $skippedRisk
        already = $already
    }
}

$sw.Stop()
$summary = @{
    all = Get-Summary $null
    L1 = Get-Summary 1
    L2 = Get-Summary 2
}
$overallScore = $summary.all.score

$output = @{
    mode = $Mode
    engine_version = "1.1.0-windows"
    duration_seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    started_at = $startedAt
    score = $overallScore
    summary = $summary
    results = @($global:Results)
    excluded = @()
    changed_files = @($global:Changed)
    engine_notes = @()
}

$output | ConvertTo-Json -Depth 4 | Out-File -FilePath $Out -Encoding utf8
Write-Host "CIS scan complete: $total rules, score=$overallScore%, pass=$($summary.all.pass), fail=$($summary.all.fail)"
Write-Host "Result written to: $Out"
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


function Protect-TempFile($Path) {
    <#
    Restrict a temporary file to the current user. Secedit exports contain
    security-policy settings and user-rights memberships; they should not be
    readable by other users while they exist.
    #>
    try {
        $acl = Get-Acl -Path $Path
        $acl.SetAccessRuleProtection($true, $false)
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $administrators = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-32-544"
        $system = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-18"
        $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        foreach ($sid in ($currentSid, $system, $administrators)) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid, "FullControl", "Allow"
            )
            $acl.AddAccessRule($rule)
        }
        Set-Acl -Path $Path -AclObject $acl
    } catch { Write-Debug "Protect-TempFile failed: $_" }
}

function Get-SecPol {
    param($Area, $Key)
    $tmp = $null
    try {
        $tmp = "$env:TEMP\secpol_$([Guid]::NewGuid()).inf"
                Protect-TempFile $tmp
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

$AuditPolicyRegMap = @{
    "1" = @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "SCENoApplyLegacyAuditPolicy"; Value = 1; Summary = "Force audit policy subcategory settings" }
    "2" = @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "CrashOnAuditFail"; Value = 0; Summary = "Shut down system if unable to log security audits" }
}

# ── Checks ─────────────────────────────────────────────────
function Invoke-Check {
    param($Rule, $Ctx)

    $id = $Rule.id
    $family = $Rule.family
    if ($family -eq "adv-audit") { $family = "audit-policy" }
    if ($family -eq "firewall") { $family = "firewall-profile" }
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
            if ($params.policy) {
                $m = $AuditPolicyRegMap[$params.policy]
                try {
                    $val = Get-ItemProperty -Path $m.Path -Name $m.Name -ErrorAction Stop | Select-Object -ExpandProperty $m.Name
                    $ok = ($val -eq $m.Value)
                    return @{status=if($ok){"pass"}else{"fail"}; detail="$($m.Summary): $($m.Name)=$val (expected $($m.Value))"}
                } catch { return @{status="error"; detail="Registry key not found: $($m.Path)\$($m.Name)"} }
            }
            $subcategory = $params.subcategory
            $expected = if ($params.expected) { $params.expected } else { "Success and Failure" }
            try {
                $out = auditpol /get /subcategory:"$subcategory" 2>&1 | Out-String
                if ($out -match "$([regex]::Escape($subcategory))\s+(.+)$") {
                    $actual = $Matches[2].Trim()
                    switch ($expected) {
                        "No Auditing"         { $ok = ($actual -eq "No Auditing") }
                        "Success"             { $ok = ($actual -eq "Success" -or $actual -eq "Success and Failure") }
                        "Failure"             { $ok = ($actual -eq "Failure" -or $actual -eq "Success and Failure") }
                        "Success and Failure" { $ok = ($actual -eq "Success and Failure") }
                        default               { $ok = ($actual -eq $expected) }
                    }
                    return @{status=if($ok){"pass"}else{"fail"}; detail="$subcategory = $actual (expected $expected)"}
                }
            } catch {}
            return @{status="error"; detail="Failed to query audit policy: $subcategory"}
        }

        # ── 4. User Rights Assignment ──
        "user-right" {
            $privilege = $params.privilege
            $expectedSid = $params.expected_sid
            if (-not $expectedSid) { return @{status="error"; detail="No expected SID for $privilege"} }
            $tmp = $null
            try {
                $tmp = "$env:TEMP\ur_$([Guid]::NewGuid()).inf"
                Protect-TempFile $tmp
                secedit /export /cfg $tmp /areas USER_RIGHTS 2>$null | Out-Null
                if (Test-Path $tmp) {
                    $content = Get-Content $tmp -Raw
                    if ($content -match "(?m)^\s*$([regex]::Escape($privilege))\s*=\s*(.+)$") {
                        $sids = $Matches[1].Trim() -split ',' | ForEach-Object { $_.Trim() }
                        $ok = ($sids -contains $expectedSid.Trim())
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
            $fwProfile = $params.profile
            $direction = if ($params.PSObject.Properties.Name -contains 'direction') { $params.direction } else { "Inbound" }
            $expectedOut = if ($params.PSObject.Properties.Name -contains 'outbound') { $params.outbound } elseif ($direction -eq "Inbound") { "Allow" } else { "Block" }
            try {
                $fw = Get-NetFirewallProfile -Name $fwProfile -ErrorAction Stop
                $ok = ($fw.Enabled -eq $true -and $fw.DefaultInboundAction -eq "Block")
                if ($direction -eq "Outbound") { $ok = $ok -and ($fw.DefaultOutboundAction -eq $expectedOut) }
                return @{
                    status = if($ok){"pass"}else{"fail"}
                    detail = "${fwProfile}: enabled=$($fw.Enabled) inbound=$($fw.DefaultInboundAction) outbound=$($fw.DefaultOutboundAction) (expected out=$expectedOut)"
                }
            } catch {
                return @{status="error"; detail="Failed to query firewall profile $fwProfile"}
            }
        }

        # ── 7. Service Configuration ──
        "service-state" {
            $name = $params.name
            $expected = $params.state
            try {
                $svc = Get-Service -Name $name -ErrorAction Stop
                $startTypes = @("Automatic", "Manual", "Disabled", "Auto", "AutomaticDelayedStart")
                $runStates  = @("Running", "Stopped", "Paused")
                if ($startTypes -contains $expected) {
                    $ok = ("$($svc.StartType)" -eq "$expected" -or ("$expected" -eq "Auto" -and "$($svc.StartType)" -eq "Automatic"))
                } elseif ($runStates -contains $expected) {
                    $ok = ("$($svc.Status)" -eq "$expected")
                } else {
                    $ok = ("$($svc.Status)" -eq "$expected" -or "$($svc.StartType)" -eq "$expected")
                }
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
    if ($family -eq "adv-audit") { $family = "audit-policy" }
    if ($family -eq "firewall") { $family = "firewall-profile" }
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
                Protect-TempFile $tmpInf
                secedit /export /cfg $tmpInf /areas SECURITYPOLICY 2>$null | Out-Null
                $c = Get-Content $tmpInf -Raw
                if ($c -match "(?m)^(\s*[^\s=]*\s*=\s*).+$") {
                    if ($c -match "(?m)^(\s*$key\s*=\s*).+$") {
                        $c = $c -replace "(?m)^(\s*$key\s*=\s*).+$", "`${1}$expected"
                    } else {
                        $c += "`r`n$key = $expected"
                    }
                    [System.IO.File]::WriteAllText($tmpInf, $c)
                    secedit /configure /db "$env:TEMP\cis-secedit-$([Guid]::NewGuid()).sdb" /cfg $tmpInf /areas SECURITYPOLICY 2>$null | Out-Null
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
                Protect-TempFile $tmpInf
                secedit /export /cfg $tmpInf /areas SECURITYPOLICY 2>$null | Out-Null
                $c = Get-Content $tmpInf -Raw
                if ($c -match "(?m)^(\s*$key\s*=\s*).+$") {
                    $c = $c -replace "(?m)^(\s*$key\s*=\s*).+$", "`${1}$expected"
                } else {
                    $c += "`r`n$key = $expected"
                }
                [System.IO.File]::WriteAllText($tmpInf, $c)
                secedit /configure /db "$env:TEMP\cis-secedit-$([Guid]::NewGuid()).sdb" /cfg $tmpInf /areas SECURITYPOLICY 2>$null | Out-Null
                Remove-Item $tmpInf -Force -ErrorAction SilentlyContinue
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "audit-policy" {
            if ($params.policy) {
                $m = $AuditPolicyRegMap[$params.policy]
                try { $cur = Get-ItemProperty -Path $m.Path -Name $m.Name -ErrorAction Stop | Select-Object -ExpandProperty $m.Name; if ($cur -eq $m.Value) { return "already" } } catch {}
                try {
                    if (-not (Test-Path $m.Path)) { New-Item -Path $m.Path -Force | Out-Null }
                    Set-ItemProperty -Path $m.Path -Name $m.Name -Value $m.Value -Type DWord -Force
                    return "applied"
                } catch { return "failed: $($_.Exception.Message)" }
            }
            $subcategory = $params.subcategory
            $expected = if ($params.expected) { $params.expected } else { "Success and Failure" }
            try {
                $out = auditpol /get /subcategory:"$subcategory" 2>&1 | Out-String
                if ($out -match "$([regex]::Escape($subcategory))\s+(.+)$") {
                    $actual = $Matches[2].Trim()
                    if ($actual -eq $expected) { return "already" }
                    $alreadyOk = $false
                    switch ($expected) {
                        "Success"             { $alreadyOk = ($actual -eq "Success" -or $actual -eq "Success and Failure") }
                        "Failure"             { $alreadyOk = ($actual -eq "Failure" -or $actual -eq "Success and Failure") }
                        "Success and Failure" { $alreadyOk = ($actual -eq "Success and Failure") }
                        "No Auditing"         { $alreadyOk = ($actual -eq "No Auditing") }
                    }
                    if ($alreadyOk) { return "already" }
                }
                $successArg = "disable"
                $failureArg = "disable"
                switch ($expected) {
                    "No Auditing"         { $successArg = "disable"; $failureArg = "disable" }
                    "Success"             { $successArg = "enable";  $failureArg = "disable" }
                    "Failure"             { $successArg = "disable"; $failureArg = "enable" }
                    "Success and Failure" { $successArg = "enable";  $failureArg = "enable" }
                    default {
                        $successArg = if ($expected -like "*Success*") { "enable" } else { "disable" }
                        $failureArg = if ($expected -like "*Failure*") { "enable" } else { "disable" }
                    }
                }
                auditpol /set /subcategory:"$subcategory" /success:$successArg /failure:$failureArg 2>$null | Out-Null
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "user-right" {
            $privilege = $params.privilege; $expectedSid = $params.expected_sid
            if (-not $expectedSid) { return "skipped: no expected SID defined" }
            $tmp = $null
            try {
                $tmp = "$env:TEMP\ur_$([Guid]::NewGuid()).inf"
                Protect-TempFile $tmp
                secedit /export /cfg $tmp /areas USER_RIGHTS 2>$null | Out-Null
                $members = @()
                if (Test-Path $tmp) {
                    $c = Get-Content $tmp -Raw
                    if ($c -match "(?m)^\s*$([regex]::Escape($privilege))\s*=\s*(.+)$") {
                        $members = $Matches[1].Trim() -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                        if ($members -contains $expectedSid.Trim()) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue; return "already" }
                    }
                    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
                }
                $tmp2 = "$env:TEMP\ur_fix_$([Guid]::NewGuid()).inf"
                Protect-TempFile $tmp2
                secedit /export /cfg $tmp2 /areas USER_RIGHTS 2>$null | Out-Null
                $c = Get-Content $tmp2 -Raw
                if ($members -notcontains $expectedSid.Trim()) {
                    $members += $expectedSid.Trim()
                }
                $members = $members | Select-Object -Unique
                $line = "$privilege = $($members -join ',')"
                if ($c -match "(?m)^(\s*$([regex]::Escape($privilege))\s*=\s*).+$") {
                    $c = $c -replace "(?m)^(\s*$([regex]::Escape($privilege))\s*=\s*).+$", "`${1}$($members -join ',')"
                } else {
                    $c += "`r`n$line"
                }
                [System.IO.File]::WriteAllText($tmp2, $c)
                $seceditDb = "$env:TEMP\cis-secedit-$([Guid]::NewGuid()).sdb"
                secedit /configure /db $seceditDb /cfg $tmp2 /areas USER_RIGHTS 2>$null | Out-Null
                $rc = $LASTEXITCODE
                Remove-Item $seceditDb -Force -ErrorAction SilentlyContinue
                Remove-Item $tmp2 -Force -ErrorAction SilentlyContinue
                if ($rc -ne 0) { return "failed: secedit exit code $rc" }
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
            $fwProfile = $params.profile
            $direction = if ($params.PSObject.Properties.Name -contains 'direction') { $params.direction } else { "Inbound" }
            $expectedOut = if ($params.PSObject.Properties.Name -contains 'outbound') { $params.outbound } elseif ($direction -eq "Inbound") { "Allow" } else { "Block" }
            try {
                $fw = Get-NetFirewallProfile -Name $fwProfile -ErrorAction Stop
                if ($fw.Enabled -eq $true -and $fw.DefaultInboundAction -eq "Block" -and $fw.DefaultOutboundAction -eq $expectedOut) { return "already" }
                Set-NetFirewallProfile -Name $fwProfile -Enabled True -DefaultInboundAction Block -DefaultOutboundAction $expectedOut
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
                    Start-Service -Name $name -ErrorAction SilentlyContinue
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

# UTF-8 WITHOUT BOM: Windows PowerShell 5.1's `Out-File -Encoding utf8`
# prefixes a BOM, and Ansible's `from_json` then dies with
# "Unexpected UTF-8 BOM" when the role parses this file.
[System.IO.File]::WriteAllText($Out, ($output | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
Write-Host "CIS scan complete: $total rules, score=$overallScore%, pass=$($summary.all.pass), fail=$($summary.all.fail)"
Write-Host "Result written to: $Out"
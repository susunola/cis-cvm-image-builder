<#
.SYNOPSIS
CIS Windows Server Benchmark - assessment engine.
Driven by rules.json catalog, outputs result.json.

.PARAMETER Catalog
Path to rules.json
.PARAMETER Mode
scan | apply
.PARAMETER Profile
L1 | L2
#>

param(
    [string]$Catalog = "rules.json",
    [string]$Mode = "scan",
    [string]$CisProfile = "L1",
    [string]$Benchmark = "",
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

# -- Helpers ------------------------------------------------
function Write-Result {
    param($Id, $Title, $Section, $Status, $Level, $Assessment = "Automated",
          $Family = "", $Risk = "safe", $Detail = "", $Page = 0, $Levels = @())
    $global:Results += [PSCustomObject]@{
        id = $Id; title = $Title; section = $Section; status = $Status
        level = $Level; assessment = $Assessment; family = $Family
        risk = $Risk; detail = $Detail; page = $Page; levels = $Levels
        duration_ms = 0; apply_status = "n/a"; apply_detail = ""
    }
}


function Protect-TempFile($Path) {
    <#
    Restrict a temporary file to the current user. Secedit exports contain
    security-policy settings and user-rights memberships; they should not be
    readable by other users while they exist. NOTE: the file must already
    exist when this is called - Get-Acl on a missing path is a no-op.
    #>
    try {
        $acl = Get-Acl -Path $Path
        $acl.SetAccessRuleProtection($true, $false)
        $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $administrators = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-32-544"
        $system = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-18"
        foreach ($sid in ($currentSid, $system, $administrators)) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid, "FullControl", "Allow"
            )
            $acl.AddAccessRule($rule)
        }
        Set-Acl -Path $Path -AclObject $acl
    } catch { Write-Debug "Protect-TempFile failed: $_" }
}

function ConvertTo-RegistryPath($Path) {
    <#
    Normalize catalog registry paths to the PSDrive-qualified form
    ("HKLM:\...") that Get-/Set-ItemProperty require. Accepts "HKLM\...",
    "HKEY_LOCAL_MACHINE\..." and already-normalized "HKLM:\...".
    #>
    if ("$Path" -match '^HKLM:\\') { return $Path }
    if ("$Path" -match '^HKEY_LOCAL_MACHINE\\') { return 'HKLM:\' + "$Path".Substring(19) }
    if ("$Path" -match '^HKLM\\') { return 'HKLM:\' + "$Path".Substring(5) }
    return $Path
}

# -- First-boot deferred hardening -------------------------------
# Rules tagged `"defer": "firstboot"` in the catalog must NOT be written to
# the registry during the build: they kill the very WinRM channel
# ansible/packer is using (CIS WinRM Service lockdown - AllowBasic=0 turns
# every subsequent pywinrm request into a 401 "credentials rejected" since
# basic auth re-authenticates per request; AllowRemoteShell=0 and UAC token
# filtering for the built-in Administrator break the follow-up tasks the
# same way).  Instead the fixer records the setting in a manifest,
# (re)generates a boot script from it, and registers a one-shot scheduled
# task that applies everything at the next boot as SYSTEM and then removes
# itself.  The captured image therefore carries the task, and every VM
# deployed from it converges on first boot.  The checker accepts a recorded
# manifest entry as compliant for golden-image purposes.
$script:FirstbootDir      = Join-Path $env:ProgramData "ohbs-image"
$script:FirstbootManifest = Join-Path $script:FirstbootDir "firstboot-deferred.json"
$script:FirstbootScript   = Join-Path $script:FirstbootDir "firstboot-hardening.ps1"
$script:FirstbootTask     = "ohbs-cis-firstboot-hardening"

function Get-FirstbootEntries {
    if (-not (Test-Path $script:FirstbootManifest)) { return @() }
    try {
        $raw = "$([System.IO.File]::ReadAllText($script:FirstbootManifest))"
        if (-not $raw.Trim()) { return @() }
        return @($raw | ConvertFrom-Json)
    } catch { return @() }
}

function Test-FirstbootDeferred($Rule) {
    $params = $Rule.params
    if (-not $params -or -not $params.path) { return $false }
    $path = ConvertTo-RegistryPath $params.path
    foreach ($e in (Get-FirstbootEntries)) {
        if ($e.path -eq $path -and "$($e.name)" -eq "$($params.name)" -and "$($e.value)" -eq "$($params.value)") { return $true }
    }
    return $false
}

function Add-FirstbootDeferred($Rule) {
    $params = $Rule.params
    $type = switch ($Rule.family) {
        "reg-string"   { "String" }
        "reg-multisz"  { "MultiString" }
        default        { "DWord" }
    }
    try {
        $entries = @(@() + (Get-FirstbootEntries))
        $path = ConvertTo-RegistryPath $params.path
        $dup = $entries | Where-Object { $_.path -eq $path -and "$($_.name)" -eq "$($params.name)" }
        if (-not $dup) {
            $entries += [PSCustomObject]@{
                path  = $path
                name  = "$($params.name)"
                type  = $type
                value = $(if ($type -eq "MultiString") { @($params.value | ForEach-Object { "$_" }) } else { $params.value })
            }
        }
        if (-not (Test-Path $script:FirstbootDir)) { New-Item -ItemType Directory -Path $script:FirstbootDir -Force | Out-Null }
        [System.IO.File]::WriteAllText($script:FirstbootManifest, ($entries | ConvertTo-Json -Depth 3), (New-Object System.Text.UTF8Encoding($false)))

        # Regenerate the boot script from the full manifest (idempotent).
        $lines = @("# ohbs-image first-boot hardening (auto-generated - do not edit)")
        foreach ($e in $entries) {
            $p = "$($e.path)".Replace("'", "''")
            $n = "$($e.name)".Replace("'", "''")
            $lines += "if (-not (Test-Path '$p')) { New-Item -Path '$p' -Force | Out-Null }"
            if ($e.type -eq "MultiString") {
                $vals = (@($e.value) | ForEach-Object { "'$("$($_)".Replace("'", "''"))'" }) -join ", "
                $lines += "Set-ItemProperty -Path '$p' -Name '$n' -Value ([string[]]@($vals)) -Type MultiString -Force"
            } elseif ($e.type -eq "DWord") {
                $lines += "Set-ItemProperty -Path '$p' -Name '$n' -Value $([int]$e.value) -Type DWord -Force"
            } else {
                $v = "$($e.value)".Replace("'", "''")
                $lines += "Set-ItemProperty -Path '$p' -Name '$n' -Value '$v' -Type String -Force"
            }
        }
        # One-shot: unregister the task and remove both files after applying.
        $lines += "Unregister-ScheduledTask -TaskName '$script:FirstbootTask' -Confirm:`$false -ErrorAction SilentlyContinue"
        $lines += "Start-Process cmd.exe -WindowStyle Hidden -ArgumentList '/c','ping 127.0.0.1 -n 3 >nul & del /q `"$($script:FirstbootScript)`" & del /q `"$($script:FirstbootManifest)`"'"
        [System.IO.File]::WriteAllText($script:FirstbootScript, ($lines -join "`r`n"), (New-Object System.Text.UTF8Encoding($false)))

        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script:FirstbootScript`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $script:FirstbootTask -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
        return "applied"
    } catch { return "failed: $($_.Exception.Message)" }
}

function ConvertTo-AccountSid($Name) {
    <#
    Resolve an account name from the catalog (e.g. "NT SERVICE\WdiServiceHost")
    to its SID string so user-right comparisons match the SID-only secedit
    export. Well-known SIDs pass through unchanged. Returns $null when the
    name cannot be resolved on this machine.
    #>
    if ("$Name" -match '^S-1-') { return "$Name" }
    try {
        return (New-Object System.Security.Principal.NTAccount("$Name")).Translate(
            [System.Security.Principal.SecurityIdentifier]).Value
    } catch {}
    # Name-hashed virtual accounts that older Windows builds cannot resolve
    # through LSA. These SIDs are deterministic (derived from the account
    # name), so a constant is safe.
    $known = @{
        'RESTRICTED SERVICES\PrintSpoolerService' = 'S-1-5-99-216390572-1995538116-3857911515-2404958512-2623887229'
    }
    if ($known.ContainsKey("$Name")) { return $known["$Name"] }
    return $null
}

function Get-UserRightMembers($Privilege) {
    <#
    Export USER_RIGHTS via secedit and return the member list of one
    privilege as @{ ok = $true; members = @(...) } (SIDs, '*' stripped).
    Returns @{ ok = $false } when the export itself failed.
    #>
    $tmp = "$env:TEMP\urq_$([Guid]::NewGuid()).inf"
    try {
        secedit /export /cfg $tmp /areas USER_RIGHTS 2>$null | Out-Null
        if (-not (Test-Path $tmp)) { return @{ ok = $false } }
        Protect-TempFile $tmp
        $content = Get-Content $tmp -Raw
        $members = @()
        if ($content -match "(?m)^\s*$([regex]::Escape($Privilege))\s*=\s*(.*)$") {
            $members = @($Matches[1].Trim() -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ })
        }
        return @{ ok = $true; members = $members }
    } catch { return @{ ok = $false } }
    finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-UserRightMatch($ExpectedSids, $Members) {
    # CIS wants exactly the expected set - no missing, no extras.
    $missing = @($ExpectedSids | Where-Object { $Members -notcontains $_ })
    $extras  = @($Members | Where-Object { $ExpectedSids -notcontains $_ })
    return ($missing.Count -eq 0 -and $extras.Count -eq 0)
}

function Get-SecPol {
    param($Area, $Key)
    $tmp = $null
    try {
        $tmp = "$env:TEMP\secpol_$([Guid]::NewGuid()).inf"
        secedit /export /cfg $tmp /areas $Area 2>$null | Out-Null
        if (Test-Path $tmp) {
            Protect-TempFile $tmp
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

function Get-AuditPolicyTable {
    <#
    auditpol localizes subcategory names AND setting strings on non-English
    images (e.g. Chinese Windows), so name/scrape matching is useless there.
    `auditpol /backup` CSV carries the locale-independent Subcategory GUID
    and a numeric Setting Value (0=none, 1=success, 2=failure, 3=both).
    Cached per run; Invoke-Fix invalidates the cache after auditpol /set.
    #>
    if ($null -ne $global:AuditTable) { return $global:AuditTable }
    $global:AuditTable = @{}
    $tmp = "$env:TEMP\auditpol_$([Guid]::NewGuid()).csv"
    try {
        auditpol /backup /file:$tmp 2>$null | Out-Null
        if (Test-Path $tmp) {
            Protect-TempFile $tmp
            foreach ($line in (Get-Content $tmp)) {
                if ($line -match '\{([0-9a-fA-F-]{36})\}.*?,(\d+)\s*$') {
                    $global:AuditTable[$Matches[1].ToLower()] = [int]$Matches[2]
                }
            }
        }
    } catch {}
    finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
    return $global:AuditTable
}

function Set-SecPolValue {
    <#
    Set one [System Access] value via secedit export/edit/import.
    Inserts the key directly under the [System Access] header when missing
    (appending at end-of-file would land it in the wrong section).
    Throws on failure so callers can report "failed: ...".
    #>
    param($Key, $Value)
    $tmpInf = "$env:TEMP\secpol_fix_$([Guid]::NewGuid()).inf"
    try {
        secedit /export /cfg $tmpInf /areas SECURITYPOLICY 2>$null | Out-Null
        if (-not (Test-Path $tmpInf)) { throw "secedit export produced no file" }
        Protect-TempFile $tmpInf
        $c = Get-Content $tmpInf -Raw
        if ($c -match "(?m)^(\s*$([regex]::Escape($Key))\s*=\s*).*$") {
            $c = $c -replace "(?m)^(\s*$([regex]::Escape($Key))\s*=\s*).*$", "`${1}$Value"
        } elseif ($c -match "(?m)^\[System Access\]\s*$") {
            $c = $c -replace "(?m)^(\[System Access\])", "`${1}`r`n$Key = $Value"
        } else {
            throw "no [System Access] section in secedit export"
        }
        [System.IO.File]::WriteAllText($tmpInf, $c)
        $db = "$env:TEMP\cis-secedit-$([Guid]::NewGuid()).sdb"
        secedit /configure /db $db /cfg $tmpInf /areas SECURITYPOLICY 2>$null | Out-Null
        $rc = $LASTEXITCODE
        Remove-Item $db -Force -ErrorAction SilentlyContinue
        if ($rc -ne 0) { throw "secedit /configure exit code $rc" }
    } finally {
        Remove-Item $tmpInf -Force -ErrorAction SilentlyContinue
    }
}

function Set-RegValue {
    <# Shared remediation for all registry-backed families. #>
    param($Path, $Name, $Value, $Type = "DWord")
    $regPath = ConvertTo-RegistryPath $Path
    $setValue = $Value
    if ($Value -is [array]) {
        # several acceptable values: compliant if any matches; enforce the
        # first (CIS-preferred) one
        try {
            $current = Get-ItemProperty -Path $regPath -Name $Name -ErrorAction Stop | Select-Object -ExpandProperty $Name
            if (($Value | Where-Object { "$current" -eq "$_" } | Select-Object -First 1) -ne $null) { return "already" }
        } catch {}
        $setValue = $Value[0]
        $Value = $Value[0]
    }
    try {
        $current = Get-ItemProperty -Path $regPath -Name $Name -ErrorAction Stop | Select-Object -ExpandProperty $Name
        if ("$current" -eq "$Value") { return "already" }
    } catch {}
    try {
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name $Name -Value $setValue -Type $Type -Force
        return "applied"
    } catch { return "failed: $($_.Exception.Message)" }
}

$AuditPolicyRegMap = @{
    "1" = @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "SCENoApplyLegacyAuditPolicy"; Value = 1; Summary = "Force audit policy subcategory settings" }
    "2" = @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "CrashOnAuditFail"; Value = 0; Summary = "Shut down system if unable to log security audits" }
}

# -- Checks -------------------------------------------------
function Invoke-Check {
    param($Rule, $Ctx)

    $id = $Rule.id
    $family = $Rule.family
    if ($family -eq "adv-audit") { $family = "audit-policy" }
    if ($family -eq "firewall") { $family = "firewall-profile" }
    $params = $Rule.params

    switch ($family) {

        # -- 1. Account Policies --
        "password-policy" {
            $key = $params.key
            $expected = $params.expected
            $op = if ($params.op) { $params.op } else { "ge" }
            $val = Get-SecPol "SECURITYPOLICY" $key
            if ($null -ne $val) {
                if ($op -eq "le") { $ok = [int]$val -le [int]$expected }
                elseif ($op -eq "eq") { $ok = [int]$val -eq [int]$expected }
                else { $ok = [int]$val -ge [int]$expected }
                $opText = @{ "ge" = ">="; "le" = "<="; "eq" = "=" }[$op]
                return @{status=if($ok){"pass"}else{"fail"}; detail="$key=$val (expected $opText$expected)"}
            }
            # Never-configured keys are absent from the secedit export; that is
            # non-compliant (fail) and remediable, not an engine error.
            return @{status="fail"; detail="$key not configured (absent from secedit export)"}
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

        # -- 2. Account Lockout --
        "lockout-policy" {
            $key = $params.key
            $expected = $params.expected
            $op = if ($params.op) { $params.op } else { "le" }
            $val = Get-SecPol "SECURITYPOLICY" $key
            if ($null -ne $val) {
                if ($op -eq "le") { $ok = [int]$val -le [int]$expected }
                elseif ($op -eq "ge") { $ok = [int]$val -ge [int]$expected }
                else { $ok = ([int]$val -eq [int]$expected) }
                if ($ok -and $params.not_zero -and [int]$val -eq 0) { $ok = $false }
                $suffix = if ($params.not_zero) { ", not 0" } else { "" }
                return @{status=if($ok){"pass"}else{"fail"}; detail="$key=$val (expected $op $expected$suffix)"}
            }
            # Absent = never configured = non-compliant (remediable)
            return @{status="fail"; detail="$key not configured (absent from secedit export)"}
        }

        # -- 3. Audit Policy --
        "audit-policy" {
            if ($params.policy) {
                $m = $AuditPolicyRegMap[$params.policy]
                try {
                    $val = Get-ItemProperty -Path $m.Path -Name $m.Name -ErrorAction Stop | Select-Object -ExpandProperty $m.Name
                    $ok = ($val -eq $m.Value)
                    return @{status=if($ok){"pass"}else{"fail"}; detail="$($m.Summary): $($m.Name)=$val (expected $($m.Value))"}
                } catch { return @{status="fail"; detail="$($m.Path)\$($m.Name) not present (expected $($m.Value))"} }
            }
            $subcategory = $params.subcategory
            $expected = if ($params.expected) { $params.expected } else { "Success and Failure" }
            # Locale-proof path: GUID lookup in the auditpol /backup CSV
            if ($params.guid) {
                $g = "$($params.guid)".Trim(' ','{','}').ToLower()
                $table = Get-AuditPolicyTable
                if ($table.ContainsKey($g)) {
                    $bits = $table[$g]
                    switch ($expected) {
                        "No Auditing"         { $ok = ($bits -eq 0) }
                        "Success"             { $ok = [bool]($bits -band 1) }
                        "Failure"             { $ok = [bool]($bits -band 2) }
                        "Success and Failure" { $ok = ($bits -eq 3) }
                        default               { $ok = ($bits -eq 3) }
                    }
                    return @{status=if($ok){"pass"}else{"fail"}; detail="$subcategory bits=$bits (expected $expected)"}
                }
            }
            # Fallback: name scrape (only works on English images)
            try {
                $out = auditpol /get /subcategory:"$subcategory" 2>$null | Out-String
                if ($out -match "(?m)$([regex]::Escape($subcategory))\s+(.+)$") {
                    $actual = $Matches[1].Trim()
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

        # -- 4. User Rights Assignment --
        "user-right" {
            $privilege = $params.privilege
            # expected_sid may be a comma-separated list of SIDs/account names;
            # empty means CIS expects "No One" (the privilege stays unassigned).
            $expected = @()
            if ("$($params.expected_sid)".Trim()) {
                $expected = "$($params.expected_sid)" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            }
            # The catalog may name accounts (e.g. "NT SERVICE\WdiServiceHost")
            # while secedit exports SIDs only - resolve names before comparing.
            $expectedSids = @($expected | ForEach-Object {
                $sid = ConvertTo-AccountSid $_
                if ($sid) { $sid } else { $_ }
            })
            $q = Get-UserRightMembers $privilege
            if ($q.ok) {
                $members = $q.members
                $ok = Test-UserRightMatch $expectedSids $members
                $expectText = if ($expected.Count -gt 0) { $expected -join ',' } else { "(No One)" }
                return @{status=if($ok){"pass"}else{"fail"}; detail="$privilege members: [$($members -join ',')] (expected [$expectText])"}
            }
            return @{status="error"; detail="Failed to query $privilege"}
        }

        # -- 5. Security Options (Registry) --
        "reg-dword" {
            $path = ConvertTo-RegistryPath $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                if ($expected -is [array]) {
                    # catalog lists several acceptable values ("0 1", "3, 5 or 11")
                    $ok = ($expected | Where-Object { "$val" -eq "$_" } | Select-Object -First 1) -ne $null
                    return @{status=if($ok){"pass"}else{"fail"}; detail="$path\$name = $val (expected one of $($expected -join '/'))"}
                }
                if ($params.op -eq "le") { $ok = [int]$val -le [int]$expected }
                elseif ($params.op -eq "ge") { $ok = [int]$val -ge [int]$expected }
                else { $ok = ("$val" -eq "$expected") }
                return @{status=if($ok){"pass"}else{"fail"}; detail="$path\$name = $val (expected $expected)"}
            } catch {
                # A policy value that is simply absent is NON-COMPLIANT (fail),
                # not an engine error - and apply mode can create it.
                return @{status="fail"; detail="$path\$name not present (expected $expected)"}
            }
        }

        "reg-string" {
            $path = ConvertTo-RegistryPath $params.path
            $name = $params.name
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ("$val" -eq "$($params.value)")
                return @{status=if($ok){"pass"}else{"fail"}; detail="$path\$name = '$val' (expected '$($params.value)')"}
            } catch { return @{status="fail"; detail="$path\$name not present (expected '$($params.value)')"} }
        }

        "reg-multisz" {
            $path = ConvertTo-RegistryPath $params.path
            $name = $params.name
            # expected is a JSON array of strings; [] means CIS wants it blank
            $expected = @()
            if ($null -ne $params.value) { $expected = @($params.value | ForEach-Object { "$_" }) }
            $actual = @()
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $actual = @($val | ForEach-Object { "$_" } | Where-Object { $_ })
            } catch { $actual = @() }  # absent == empty
            $missingE = @($expected | Where-Object { $actual -notcontains $_ })
            $extraE   = @($actual | Where-Object { $expected -notcontains $_ })
            $ok = ($missingE.Count -eq 0 -and $extraE.Count -eq 0)
            return @{status=if($ok){"pass"}else{"fail"}; detail="$path\$name = [$($actual -join ',')] (expected [$($expected -join ',')])"}
        }

        "reg-exists" {
            $path = ConvertTo-RegistryPath $params.path
            $ok = Test-Path $path
            return @{status=if($ok){"pass"}else{"fail"}; detail="$path exists=$ok"}
        }

        "reg-values-map" {
            # Rules expressed as a SET of string values under one key —
            # e.g. win2016 18.10.43.6.1.2 (ASR per-rule states: 15 REG_SZ
            # GUID values = "1" under ...\Exploit Guard\ASR\Rules).
            # params: {path, values: {name: expected-string, ...}}
            $path = ConvertTo-RegistryPath $params.path
            $entries = @($params.values.PSObject.Properties)
            $bad = @()
            foreach ($kv in $entries) {
                $name = $kv.Name
                $expected = "$($kv.Value)"
                try {
                    $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                    if ("$val" -ne $expected) { $bad += "$name='$val' (expected '$expected')" }
                } catch { $bad += "$name not present (expected '$expected')" }
            }
            $ok = ($bad.Count -eq 0)
            if ($ok) { return @{status="pass"; detail="${path}: all $($entries.Count) value(s) match"} }
            return @{status="fail"; detail="${path}: $($bad -join '; ')"}
        }

        # -- 6. Windows Firewall --
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

        # -- 7. Service Configuration --
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

        # -- 8. Windows Update --
        "wu-config" {
            $path = ConvertTo-RegistryPath $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ($val -eq $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="WindowsUpdate\$name = $val (expected $expected)"}
            } catch { return @{status="fail"; detail="$path\$name not present (expected $expected)"} }
        }

        # -- 9. UAC --
        "uac" {
            $path = ConvertTo-RegistryPath $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ($val -eq $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="UAC\$name = $val (expected $expected)"}
            } catch { return @{status="fail"; detail="$path\$name not present (expected $expected)"} }
        }

        # -- 10. Network Security --
        "lanman-auth" {
            $path = ConvertTo-RegistryPath $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ([int]$val -ge [int]$expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="LmCompatibilityLevel = $val (expected >=$expected)"}
            } catch { return @{status="fail"; detail="$path\$name not present (expected >=$expected)"} }
        }

        "smb-signing" {
            $path = ConvertTo-RegistryPath $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ($val -eq $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="SMB\$name = $val (expected $expected)"}
            } catch { return @{status="fail"; detail="$path\$name not present (expected $expected)"} }
        }

        # -- 11. RDP Security --
        "rdp-nla" {
            $path = ConvertTo-RegistryPath $params.path
            $name = $params.name
            $expected = $params.value
            try {
                $val = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $ok = ($val -eq $expected)
                return @{status=if($ok){"pass"}else{"fail"}; detail="RDP NLA = $val (expected $expected)"}
            } catch { return @{status="fail"; detail="$path\$name not present (expected $expected)"} }
        }

        # -- 12. Event Log --
        "eventlog-size" {
            $logName = $params.log
            $expectedMB = $params.min_size_mb
            try {
                $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
                $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 0)
                $ok = ($sizeMB -ge $expectedMB)
                return @{status=if($ok){"pass"}else{"fail"}; detail="$logName max=$sizeMB MB (expected >=$expectedMB MB)"}
            } catch { return @{status="error"; detail="Event log $logName not found"} }
        }

        # -- 13. PowerShell Security --
        "ps-execution" {
            try {
                $policy = Get-ExecutionPolicy -Scope LocalMachine
                $ok = ($policy -eq "RemoteSigned" -or $policy -eq "Restricted" -or $policy -eq "AllSigned")
                return @{status=if($ok){"pass"}else{"fail"}; detail="ExecutionPolicy=$policy"}
            } catch { return @{status="error"; detail="Failed to query execution policy"} }
        }

        "ps-logging" {
            $path = ConvertTo-RegistryPath $params.path
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

# -- Apply (Remediation) -------------------------------------
function Invoke-Fix {
    param($Rule)

    # Deferred rules never touch the live registry during the build (see the
    # first-boot block above); they are recorded and applied at next boot.
    if (($Rule.PSObject.Properties.Name -contains 'defer') -and $Rule.defer -eq "firstboot") {
        return Add-FirstbootDeferred $Rule
    }

    $family = $Rule.family
    if ($family -eq "adv-audit") { $family = "audit-policy" }
    if ($family -eq "firewall") { $family = "firewall-profile" }
    $params = $Rule.params

    switch ($family) {

        "password-policy" {
            $key = $params.key; $expected = $params.expected
            $op = if ($params.op) { $params.op } else { "ge" }
            $val = Get-SecPol "SECURITYPOLICY" $key
            $isOk = $false
            if ($null -ne $val) {
                if ($op -eq "le") { $isOk = [int]$val -le [int]$expected }
                elseif ($op -eq "eq") { $isOk = [int]$val -eq [int]$expected }
                else { $isOk = [int]$val -ge [int]$expected }
            }
            if ($isOk) { return "already" }
            try {
                Set-SecPolValue $key $expected
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "password-complexity" {
            $val = Get-SecPol "SECURITYPOLICY" "PasswordComplexity"
            if ($val -eq "1") { return "already" }
            try {
                Set-SecPolValue "PasswordComplexity" 1
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "password-reversible" {
            $val = Get-SecPol "SECURITYPOLICY" "ClearTextPassword"
            if ($val -eq "0") { return "already" }
            try {
                Set-SecPolValue "ClearTextPassword" 0
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "lockout-policy" {
            $key = $params.key; $expected = $params.expected
            $op = if ($params.op) { $params.op } else { "le" }
            $val = Get-SecPol "SECURITYPOLICY" $key
            $isOk = $false
            if ($null -ne $val) {
                if ($op -eq "le") { $isOk = [int]$val -le [int]$expected }
                elseif ($op -eq "ge") { $isOk = [int]$val -ge [int]$expected }
                else { $isOk = [int]$val -eq [int]$expected }
            }
            if ($isOk) { return "already" }
            # net accounts is the canonical, locale-free path for the three
            # lockout settings (secedit exports omit them until configured, and
            # the INF key for the threshold is LockoutBadCount). Duration and
            # window do not persist while the threshold is 0 ("Never"), and the
            # duration may not be below the window -- so apply all three catalog
            # values together, in a dependency-safe way.
            $netMap = @{ "LockoutDuration" = "lockoutduration"; "LockoutBadCount" = "lockoutthreshold"; "ResetLockoutCount" = "lockoutwindow" }
            if ($netMap.ContainsKey($key)) {
                try {
                    $thr = 5; $win = 15; $dur = 15
                    foreach ($sib in $script:ruleCatalog) {
                        if ($sib.family -ne "lockout-policy") { continue }
                        switch ($sib.params.key) {
                            "LockoutBadCount"   { $thr = [int]$sib.params.expected }
                            "ResetLockoutCount" { $win = [int]$sib.params.expected }
                            "LockoutDuration"   { $dur = [int]$sib.params.expected }
                        }
                    }
                    if ($dur -lt $win) { $dur = $win }
                    net accounts "/lockoutthreshold:$thr" "/lockoutwindow:$win" "/lockoutduration:$dur" 2>$null | Out-Null
                    if ($LASTEXITCODE -ne 0) { return "failed: net accounts exit $LASTEXITCODE" }
                    return "applied"
                } catch { return "failed: $($_.Exception.Message)" }
            }
            try {
                Set-SecPolValue $key $expected
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
            # GUID targets are locale-proof (Chinese images localize names)
            $target = if ($params.guid) { "{$("$($params.guid)".Trim(' ','{','}'))}" } else { $subcategory }
            if ($params.guid) {
                $g = "$($params.guid)".Trim(' ','{','}').ToLower()
                $table = Get-AuditPolicyTable
                if ($table.ContainsKey($g)) {
                    $bits = $table[$g]
                    $alreadyOk = $false
                    switch ($expected) {
                        "Success"             { $alreadyOk = [bool]($bits -band 1) }
                        "Failure"             { $alreadyOk = [bool]($bits -band 2) }
                        "Success and Failure" { $alreadyOk = ($bits -eq 3) }
                        "No Auditing"         { $alreadyOk = ($bits -eq 0) }
                    }
                    if ($alreadyOk) { return "already" }
                }
            }
            # The name-scrape below only works on English images; skip it when a
            # locale-proof GUID is available (the bits check above already ran).
            if (-not $params.guid) {
                try {
                    $out = auditpol /get /subcategory:"$subcategory" 2>$null | Out-String
                    if ($out -match "(?m)$([regex]::Escape($subcategory))\s+(.+)$") {
                        $actual = $Matches[1].Trim()
                        $alreadyOk = $false
                        switch ($expected) {
                            "Success"             { $alreadyOk = ($actual -eq "Success" -or $actual -eq "Success and Failure") }
                            "Failure"             { $alreadyOk = ($actual -eq "Failure" -or $actual -eq "Success and Failure") }
                            "Success and Failure" { $alreadyOk = ($actual -eq "Success and Failure") }
                            "No Auditing"         { $alreadyOk = ($actual -eq "No Auditing") }
                        }
                        if ($alreadyOk) { return "already" }
                    }
                } catch {}
            }
            try {
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
                auditpol /set /subcategory:"$target" /success:$successArg /failure:$failureArg 2>$null | Out-Null
                if ($LASTEXITCODE -ne 0) { return "failed: auditpol /set exit $LASTEXITCODE" }
                $global:AuditTable = $null  # invalidate the cached backup CSV
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }

        "user-right" {
            $privilege = $params.privilege
            $expected = @()
            if ("$($params.expected_sid)".Trim()) {
                $expected = "$($params.expected_sid)" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            }
            $tmp = $null
            try {
                $tmp = "$env:TEMP\ur_fix_$([Guid]::NewGuid()).inf"
                secedit /export /cfg $tmp /areas USER_RIGHTS 2>$null | Out-Null
                if (-not (Test-Path $tmp)) { return "failed: secedit export produced no file" }
                Protect-TempFile $tmp
                $c = Get-Content $tmp -Raw
                $members = @()
                if ($c -match "(?m)^\s*$([regex]::Escape($privilege))\s*=\s*(.*)$") {
                    $members = $Matches[1].Trim() -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ }
                }
                # Compare in SID space: the catalog may name accounts while the
                # secedit export lists SIDs only.
                $expectedSids = @($expected | ForEach-Object {
                    $sid = ConvertTo-AccountSid $_
                    if ($sid) { $sid } else { $_ }
                })
                $missing = @($expectedSids | Where-Object { $members -notcontains $_ })
                $extras  = @($members | Where-Object { $expectedSids -notcontains $_ })
                if ($missing.Count -eq 0 -and $extras.Count -eq 0) { return "already" }
                if ($expected.Count -eq 0) {
                    # CIS "No One": an empty assignment revokes every member
                    $written = @()
                    if ($c -match "(?m)^\s*$([regex]::Escape($privilege))\s*=.*$") {
                        $c = $c -replace "(?m)^\s*$([regex]::Escape($privilege))\s*=.*$", "$privilege ="
                    } else {
                        return "already"  # no assignment line means no members
                    }
                    [System.IO.File]::WriteAllText($tmp, $c)
                    $seceditDb = "$env:TEMP\cis-secedit-$([Guid]::NewGuid()).sdb"
                    secedit /configure /db $seceditDb /cfg $tmp /areas USER_RIGHTS 2>$null | Out-Null
                    $rc = $LASTEXITCODE
                    Remove-Item $seceditDb -Force -ErrorAction SilentlyContinue
                    if ($rc -ne 0) {
                        # Some localized builds (zh-CN Server 2025) exit 1 even
                        # when the import succeeded - verify before failing.
                        $verify = Get-UserRightMembers $privilege
                        if ($verify.ok -and $verify.members.Count -eq 0) { return "applied" }
                        return "failed: secedit exit code $rc"
                    }
                    return "applied"
                }
                # secedit imports SIDs with a leading '*'; account names stay
                # bare, but resolving names to SIDs first also works on Windows
                # builds whose secedit cannot resolve the name itself.
                # CIS wants exactly the expected set, so replace - not merge.
                $written = $expected | ForEach-Object {
                    if ($_ -match '^S-1-') { "*$_" }
                    else {
                        $sid = ConvertTo-AccountSid $_
                        if ($sid) { "*$sid" } else { $_ }
                    }
                }
                $line = "$privilege = $($written -join ',')"
                if ($c -match "(?m)^(\s*$([regex]::Escape($privilege))\s*=\s*).*$") {
                    $c = $c -replace "(?m)^(\s*$([regex]::Escape($privilege))\s*=\s*).*$", "`${1}$($written -join ',')"
                } elseif ($c -match "(?m)^\[Privilege Rights\]\s*$") {
                    $c = $c -replace "(?m)^(\[Privilege Rights\])", "`${1}`r`n$line"
                } else {
                    $c += "`r`n[Privilege Rights]`r`n$line"
                }
                [System.IO.File]::WriteAllText($tmp, $c)
                $seceditDb = "$env:TEMP\cis-secedit-$([Guid]::NewGuid()).sdb"
                secedit /configure /db $seceditDb /cfg $tmp /areas USER_RIGHTS 2>$null | Out-Null
                $rc = $LASTEXITCODE
                Remove-Item $seceditDb -Force -ErrorAction SilentlyContinue
                if ($rc -ne 0) {
                    # Some localized builds (zh-CN Server 2025) exit 1 even when
                    # the import succeeded - verify before failing.
                    $verify = Get-UserRightMembers $privilege
                    if ($verify.ok -and (Test-UserRightMatch $expectedSids $verify.members)) { return "applied" }
                    return "failed: secedit exit code $rc"
                }
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
            finally {
                if ($tmp -and (Test-Path $tmp)) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
            }
        }

        "reg-dword"  { return Set-RegValue $params.path $params.name $params.value "DWord" }
        "reg-values-map" {
            $regPath = ConvertTo-RegistryPath $params.path
            try {
                if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                foreach ($kv in @($params.values.PSObject.Properties)) {
                    Set-ItemProperty -Path $regPath -Name $kv.Name -Value "$($kv.Value)" -Type String -Force
                }
                return "applied"
            } catch { return "failed: $($_.Exception.Message)" }
        }
        "reg-string" { return Set-RegValue $params.path $params.name $params.value "String" }
        "uac"        { return Set-RegValue $params.path $params.name $params.value "DWord" }
        "wu-config"  { return Set-RegValue $params.path $params.name $params.value "DWord" }
        "lanman-auth" { return Set-RegValue $params.path $params.name $params.value "DWord" }
        "smb-signing" { return Set-RegValue $params.path $params.name $params.value "DWord" }
        "rdp-nla"    { return Set-RegValue $params.path $params.name $params.value "DWord" }

        "reg-multisz" {
            $regPath = ConvertTo-RegistryPath $params.path
            $name = $params.name
            $expected = @()
            if ($null -ne $params.value) { $expected = @($params.value | ForEach-Object { "$_" }) }
            $actual = @()
            try {
                $val = Get-ItemProperty -Path $regPath -Name $name -ErrorAction Stop | Select-Object -ExpandProperty $name
                $actual = @($val | ForEach-Object { "$_" } | Where-Object { $_ })
            } catch {}
            $missingE = @($expected | Where-Object { $actual -notcontains $_ })
            $extraE   = @($actual | Where-Object { $expected -notcontains $_ })
            if ($missingE.Count -eq 0 -and $extraE.Count -eq 0) { return "already" }
            try {
                if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                Set-ItemProperty -Path $regPath -Name $name -Value ([string[]]$expected) -Type MultiString -Force
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
                $startTypes = @("Automatic", "Manual", "Disabled", "Auto", "AutomaticDelayedStart")
                if ($startTypes -contains $expected -and "$($svc.StartType)" -eq $expected) { return "already" }
                if ($expected -eq "Stopped" -and $svc.Status -eq "Stopped") { return "already" }
                if ($expected -eq "Running" -and $svc.Status -eq "Running") { return "already" }
                if ($expected -eq "Stopped" -or $expected -eq "Disabled") {
                    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $name -StartupType Disabled
                } elseif ($expected -eq "Running" -or $expected -eq "Auto" -or $expected -eq "Automatic") {
                    Set-Service -Name $name -StartupType Automatic
                    Start-Service -Name $name -ErrorAction SilentlyContinue
                } elseif ($expected -eq "Manual") {
                    Set-Service -Name $name -StartupType Manual
                }
                return "applied"
            } catch {
                if ($expected -eq "NotFound") { return "already" }
                return "failed: $($_.Exception.Message)"
            }
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

        "ps-logging" { return Set-RegValue $params.path $params.name $params.value "DWord" }

        default { return "skipped: no fix for family $family" }
    }
}

# -- Load Rules ----------------------------------------------
try {
    $raw = [System.IO.File]::ReadAllText($Catalog)
    # NOTE: do NOT name this $catalog -- the [string]$Catalog param is a typed
    # variable and PowerShell names are case-insensitive, so the assignment
    # would coerce the parsed array back into a string (0 rules evaluated).
    $ruleCatalog = $raw | ConvertFrom-Json
    if (-not $ruleCatalog -or $ruleCatalog.Count -eq 0) {
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
foreach ($r in $ruleCatalog) {
    # Level filter
    if ($CisProfile -eq "L1" -and $r.levels -notcontains 1) { continue }
    # Platform filter
    if ($Platform -and $r.platforms -and $r.platforms -notcontains $Platform) { continue }
    # Exclude - must check BEFORE adding to $rules
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

# -- Execute -------------------------------------------------
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

    # Controls the engine cannot evaluate are never remediated - report them
    # as manual so they neither count as pass nor are silently "fixed".
    # family "manual" means the catalog has no machine-checkable params.
    if ($rule.family -eq "manual" -or (($rule.PSObject.Properties.Name -contains 'automated') -and ($rule.automated -eq $false))) {
        Write-Result -Id $rule.id -Title $rule.title -Section $rule.section `
            -Status "manual" -Level ($rule.levels | Select-Object -First 1) `
            -Assessment $rule.assessment -Family $rule.family `
            -Risk $rule.risk -Detail "manual control (not automated)" -Page $rule.page `
            -Levels @($rule.levels)
        $global:Results[-1].apply_status = "n/a"
        continue
    }

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
                    # Re-check so the recorded status (and the gate score) reflects
                    # the post-fix state, not the pre-fix fail.
                    $result = Invoke-Check -Rule $rule
                    if ($result.status -eq "fail" -and ($rule.PSObject.Properties.Name -contains 'defer') -and $rule.defer -eq "firstboot" -and (Test-FirstbootDeferred $rule)) {
                        $result = @{status="pass"; detail="$($result.detail) [remediation deferred to first boot via scheduled task $script:FirstbootTask]"}
                    }
                }
            } catch {
                $applyStatus = "failed: $($_.Exception.Message)"
            }
        }
    } elseif ($isApply -and $result.status -eq "pass") {
        $applyStatus = "already"
    } elseif (-not $isApply -and $result.status -eq "fail") {
        # scan mode: a rule whose remediation is already queued for first boot
        # counts as compliant - the image carries the one-shot task.
        if (($rule.PSObject.Properties.Name -contains 'defer') -and $rule.defer -eq "firstboot" -and (Test-FirstbootDeferred $rule)) {
            $result = @{status="pass"; detail="$($result.detail) [remediation deferred to first boot via scheduled task $script:FirstbootTask]"}
        }
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

# -- Summary -------------------------------------------------
function Get-Summary($levelFilter) {
    $filtered = if ($levelFilter) { $global:Results | Where-Object { $_.level -eq $levelFilter } } else { $global:Results }
    # NOTE: @(...) is mandatory - a pipeline yielding exactly one PSCustomObject
    # has no .Count member in Windows PowerShell 5.1, which turned a lone fail
    # into $null and silently dropped it from the score arithmetic.
    $pass = @($filtered | Where-Object { $_.status -eq "pass" }).Count
    $fail = @($filtered | Where-Object { $_.status -eq "fail" }).Count
    $manual = @($filtered | Where-Object { $_.status -eq "manual" }).Count
    $error = @($filtered | Where-Object { $_.status -eq "error" }).Count
    $na = @($filtered | Where-Object { $_.status -eq "notapplicable" }).Count
    $total = @($filtered).Count
    # Errors are NOT compliance - count them against the score so a catalog that
    # cannot evaluate a rule can never fake a passing grade (they'd otherwise be
    # dropped from the denominator and inflate the score).
    $assessed = $pass + $fail + $error
    $score = if ($assessed -gt 0) { [math]::Round(100.0 * $pass / $assessed, 1) } else { 0.0 }

    # Apply stats
    $applied = @($filtered | Where-Object { $_.apply_status -eq "applied" }).Count
    $applyFailed = @($filtered | Where-Object { $_.apply_status -match "^failed" }).Count
    $skippedRisk = @($filtered | Where-Object { $_.apply_status -eq "skipped_disruptive" }).Count
    $already = @($filtered | Where-Object { $_.apply_status -eq "already" }).Count
    # Known simplification: rules.json carries no reboot-required marker, so
    # applied_pending is hardcoded 0 even though registry/audit-policy/some
    # security-option changes need a reboot or gpupdate to take effect.  There
    # is no data to tally (unlike Linux); revisit if rules gain a reboot flag.
    $appliedPending = 0

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
    benchmark = $Benchmark
    engine_version = "1.2.0-windows"
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

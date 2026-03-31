<#
================================================================================
  AttackPathCanvas -- Visualize Identity Attack Paths in Active Directory
  Version: 1.1
  Author : Santhosh Sivarajan, Microsoft MVP
  Purpose: Discovers and visualizes identity attack paths by analyzing
           privileged group membership chains, OU delegation escalation
           paths, service account risks, and Tier 0 exposure. Produces
           an interactive HTML report with SVG attack path diagrams.
  License: MIT -- Free to use, modify, and distribute.
  GitHub : https://github.com/SanthoshSivarajan/AttackPathCanvas
================================================================================
#>

#Requires -Modules ActiveDirectory

param([string]$OutputPath = $PSScriptRoot)

$ReportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
$OutputFile = Join-Path $OutputPath "AttackPathCanvas_$ReportDate.html"

Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  |   AttackPathCanvas -- Identity Attack Path Visualizer v1.1 |" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  |   Author : Santhosh Sivarajan, Microsoft MVP              |" -ForegroundColor Cyan
Write-Host "  |   Web    : github.com/SanthoshSivarajan/AttackPathCanvas  |" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host ""

Import-Module ActiveDirectory -ErrorAction Stop

$now = Get-Date
$Forest = Get-ADForest -ErrorAction Stop
$ForestName = $Forest.Name

Write-Host "  [*] Forest    : $ForestName" -ForegroundColor White
Write-Host "  [*] Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host ""

# --- Helpers ------------------------------------------------------------------
Add-Type -AssemblyName System.Web
function HtmlEncode($s) { if ($null -eq $s) { return "--" }; return [System.Web.HttpUtility]::HtmlEncode([string]$s) }

# GUID maps for delegation analysis
$rootDSE = Get-ADRootDSE
$GUIDMap = @{}
try {
    Get-ADObject -SearchBase $rootDSE.schemaNamingContext -LDAPFilter "(schemaIDGUID=*)" -Properties lDAPDisplayName,schemaIDGUID -Server $rootDSE.dnsHostName -ErrorAction Stop | ForEach-Object {
        if ($_.schemaIDGUID) { $GUIDMap[([System.GUID]$_.schemaIDGUID).Guid.ToLower()] = $_.lDAPDisplayName }
    }
} catch { }
try {
    Get-ADObject -SearchBase "CN=Extended-Rights,$($rootDSE.configurationNamingContext)" -LDAPFilter "(objectClass=controlAccessRight)" -Properties displayName,rightsGuid -Server $rootDSE.dnsHostName -ErrorAction Stop | ForEach-Object {
        if ($_.rightsGuid) { $GUIDMap[$_.rightsGuid.ToLower()] = $_.displayName }
    }
} catch { }
$GUIDMap['00000000-0000-0000-0000-000000000000'] = 'All'
function Resolve-GUID([string]$g) { if ($GUIDMap.ContainsKey($g.ToLower())) { return $GUIDMap[$g.ToLower()] }; return $g }

# Built-in filter
$BuiltInIdentities = @('NT AUTHORITY\SYSTEM','NT AUTHORITY\SELF','NT AUTHORITY\Authenticated Users','BUILTIN\Administrators','BUILTIN\Account Operators','BUILTIN\Server Operators','BUILTIN\Print Operators','BUILTIN\Backup Operators','BUILTIN\Pre-Windows 2000 Compatible Access','CREATOR OWNER','Everyone','ENTERPRISE DOMAIN CONTROLLERS','NT AUTHORITY\NETWORK SERVICE')
function Test-BuiltIn([string]$id) {
    if ($id -in $BuiltInIdentities) { return $true }
    if ($id -match '^S-1-5-32-|^S-1-5-9|^S-1-3-0|^S-1-5-18|^S-1-5-10|^S-1-5-11|^S-1-1-0') { return $true }
    if ($id -match '\\Domain Admins$|\\Enterprise Admins$|\\Schema Admins$|\\Administrators$|\\Domain Controllers$') { return $true }
    return $false
}

Write-Host "  [*] Discovering attack paths across all domains ..." -ForegroundColor Yellow
Write-Host ""

# ==============================================================================
# PHASE 1: COLLECT PRIVILEGED GROUP MEMBERSHIP (ALL DOMAINS)
# ==============================================================================
Write-Host "  --- Phase 1: Privileged Group Membership ---" -ForegroundColor Cyan

$Tier0Groups = @(
    @{Name='Domain Admins';       Impact='Full control over the domain -- can modify any object, reset any password, log on to any DC'}
    @{Name='Enterprise Admins';   Impact='Full control over the ENTIRE FOREST -- can modify any domain in the forest'}
    @{Name='Schema Admins';       Impact='Can modify Active Directory schema -- changes are IRREVERSIBLE and affect entire forest'}
    @{Name='Administrators';      Impact='Full administrative control of domain controllers -- built-in admin group'}
    @{Name='Account Operators';   Impact='Can create, modify, and delete user accounts and groups -- legacy operator group'}
    @{Name='Server Operators';    Impact='Can log on to DCs, manage services, backup files, and shut down DCs'}
    @{Name='Print Operators';     Impact='Can log on to DCs and load printer drivers (kernel-level code execution on DCs)'}
    @{Name='Backup Operators';    Impact='Can read ANY file on DCs including NTDS.dit (contains all password hashes)'}
    @{Name='DnsAdmins';           Impact='Can load arbitrary DLLs into the DNS service process (often runs on DCs)'}
)

$AllPaths = [System.Collections.Generic.List[object]]::new()
$PrincipalProfiles = @{}
$GroupMemberMap = @{}

$allDomains = @()
foreach ($d in $Forest.Domains) { $allDomains += $d }

foreach ($domainName in $allDomains) {
    Write-Host "  [*] Domain: $domainName" -ForegroundColor White
    $server = $null
    try {
        $domObj = Get-ADDomain -Identity $domainName -ErrorAction Stop
        $server = $domObj.PDCEmulator
    } catch { continue }

    foreach ($grp in $Tier0Groups) {
        try {
            # Direct members
            $directMembers = @(Get-ADGroupMember -Identity $grp.Name -Server $server -ErrorAction Stop)
            # Recursive (effective) members
            $recursiveMembers = @()
            try { $recursiveMembers = @(Get-ADGroupMember -Identity $grp.Name -Server $server -Recursive -ErrorAction SilentlyContinue) } catch { }

            foreach ($m in $directMembers) {
                $isGroup = ($m.objectClass -eq 'group')
                $isServiceAcct = $false
                $isDisabled = $false
                $nestedEffective = 0
                $memberOf = @()

                try {
                    if ($m.objectClass -eq 'user') {
                        $usr = Get-ADUser $m.SID -Server $server -Properties Enabled,servicePrincipalName,MemberOf -ErrorAction SilentlyContinue
                        $isDisabled = -not $usr.Enabled
                        $isServiceAcct = ($usr.servicePrincipalName -and @($usr.servicePrincipalName).Count -gt 0)
                        $memberOf = @($usr.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' })
                    } elseif ($isGroup) {
                        try { $nestedEffective = @(Get-ADGroupMember -Identity $m.SID -Server $server -Recursive -ErrorAction SilentlyContinue).Count } catch { }
                    }
                } catch { }

                # Build membership chain
                $chain = "$($m.Name) -> $($grp.Name)"
                if ($isGroup) { $chain = "[Group] $($m.Name) ($nestedEffective users) -> $($grp.Name)" }

                # Determine path risk
                $pathRisk = 'High'
                if ($grp.Name -in @('Enterprise Admins','Schema Admins')) { $pathRisk = 'Critical' }
                if ($grp.Name -in @('Account Operators','Server Operators','Print Operators','Backup Operators')) { $pathRisk = 'Critical' }
                if ($isServiceAcct) { $pathRisk = 'Critical' }
                if ($isDisabled) { $pathRisk = 'High' }

                # Risk reason
                $riskReason = "Direct member of $($grp.Name)"
                if ($isServiceAcct) { $riskReason = "SERVICE ACCOUNT in $($grp.Name) -- credentials may be on multiple servers" }
                if ($isDisabled) { $riskReason = "DISABLED account still in $($grp.Name) -- remove immediately" }
                if ($isGroup) { $riskReason = "Nested group with $nestedEffective effective users in $($grp.Name)" }
                if ($grp.Name -in @('Account Operators','Server Operators','Print Operators','Backup Operators') -and -not $isGroup) {
                    $riskReason = "Member of $($grp.Name) -- this group should be EMPTY"
                }

                $AllPaths.Add([PSCustomObject]@{
                    Domain=$domainName; PathType='Privileged Group'; Principal=$m.Name;
                    PrincipalType=$m.objectClass; IsServiceAccount=$isServiceAcct;
                    IsDisabled=$isDisabled; Target=$grp.Name; Chain=$chain;
                    Impact=$grp.Impact; Risk=$pathRisk; RiskReason=$riskReason;
                    Category='Group Membership'
                })

                # Build principal profile
                $pKey = "$($m.Name)@$domainName"
                if (-not $PrincipalProfiles.ContainsKey($pKey)) {
                    $PrincipalProfiles[$pKey] = @{Name=$m.Name;Domain=$domainName;Type=$m.objectClass;Groups=@();Delegations=@();Risks=@();IsServiceAccount=$isServiceAcct;IsDisabled=$isDisabled}
                }
                $PrincipalProfiles[$pKey].Groups += "$($grp.Name) ($domainName)"
            }

            $GroupMemberMap["$($grp.Name)@$domainName"] = @{Direct=$directMembers.Count;Effective=$recursiveMembers.Count}
        } catch { }
    }
}
Write-Host "  [+] Privileged group paths: $($AllPaths.Count)" -ForegroundColor Green

# --- Phase 1B: Nested Group Chain Walking ---
# Walk nested groups to find hidden users and build full chain paths
Write-Host ""
Write-Host "  --- Phase 1B: Nested Group Chain Expansion ---" -ForegroundColor Cyan

function Get-NestedChainUsers {
    param([string]$GroupSID, [string]$Server, [string]$ChainSoFar, [int]$Depth, [int]$MaxDepth = 10, [hashtable]$Visited)
    if ($Depth -ge $MaxDepth) { return @() }
    if ($Visited.ContainsKey($GroupSID)) { return @() }
    $Visited[$GroupSID] = $true
    $results = @()
    try {
        $members = @(Get-ADGroupMember -Identity $GroupSID -Server $Server -ErrorAction Stop)
        foreach ($m in $members) {
            $newChain = "$($m.Name) -> $ChainSoFar"
            if ($m.objectClass -eq 'user') {
                $isDisabled = $false; $isSvc = $false
                try {
                    $u = Get-ADUser $m.SID -Server $Server -Properties Enabled,servicePrincipalName -ErrorAction SilentlyContinue
                    $isDisabled = -not $u.Enabled
                    $isSvc = ($u.servicePrincipalName -and @($u.servicePrincipalName).Count -gt 0)
                } catch { }
                $results += [PSCustomObject]@{Name=$m.Name;SID=$m.SID;Chain=$newChain;Depth=($Depth+1);IsDisabled=$isDisabled;IsServiceAccount=$isSvc;objectClass='user'}
            } elseif ($m.objectClass -eq 'group') {
                $subResults = Get-NestedChainUsers -GroupSID $m.SID -Server $Server -ChainSoFar $newChain -Depth ($Depth+1) -MaxDepth $MaxDepth -Visited $Visited
                $results += $subResults
            }
        }
    } catch { }
    return $results
}

$NestedChainPaths = [System.Collections.Generic.List[object]]::new()
foreach ($domainName in $allDomains) {
    $server = $null
    try { $domObj = Get-ADDomain -Identity $domainName -ErrorAction Stop; $server = $domObj.PDCEmulator } catch { continue }

    foreach ($grp in $Tier0Groups) {
        try {
            $directMembers = @(Get-ADGroupMember -Identity $grp.Name -Server $server -ErrorAction Stop)
            foreach ($m in $directMembers) {
                if ($m.objectClass -ne 'group') { continue }
                # Walk this nested group to find all users inside
                $visited = @{}
                $chainStart = "$($m.Name) -> $($grp.Name)"
                $nestedUsers = Get-NestedChainUsers -GroupSID $m.SID -Server $server -ChainSoFar $chainStart -Depth 1 -MaxDepth 10 -Visited $visited

                foreach ($nu in $nestedUsers) {
                    if ($nu.Depth -lt 2) { continue }  # Skip depth=1 (already shown as direct members of nested group)

                    $pathRisk = 'Critical'
                    $riskReason = "HIDDEN ADMIN: $($nu.Depth)-level deep nesting to $($grp.Name)"
                    if ($nu.IsServiceAccount) { $riskReason = "HIDDEN SERVICE ACCOUNT: $($nu.Depth)-level deep nesting to $($grp.Name)" }
                    if ($nu.IsDisabled) { $riskReason = "HIDDEN DISABLED ACCOUNT: $($nu.Depth)-level deep nesting to $($grp.Name)" }

                    $impact = "User is $($nu.Depth) groups deep from $($grp.Name) -- effectively a domain admin but invisible in standard tools. Chain: $($nu.Chain)"

                    $AllPaths.Add([PSCustomObject]@{
                        Domain=$domainName; PathType='Nested Group Chain'; Principal=$nu.Name;
                        PrincipalType=$nu.objectClass; IsServiceAccount=$nu.IsServiceAccount;
                        IsDisabled=$nu.IsDisabled; Target=$grp.Name; Chain=$nu.Chain;
                        Impact=$impact; Risk=$pathRisk; RiskReason=$riskReason;
                        Category='Nested Chain'
                    })

                    $NestedChainPaths.Add([PSCustomObject]@{
                        Domain=$domainName; User=$nu.Name; TargetGroup=$grp.Name;
                        Chain=$nu.Chain; Depth=$nu.Depth; IsServiceAccount=$nu.IsServiceAccount;
                        IsDisabled=$nu.IsDisabled; Risk=$pathRisk
                    })

                    $pKey = "$($nu.Name)@$domainName"
                    if (-not $PrincipalProfiles.ContainsKey($pKey)) {
                        $PrincipalProfiles[$pKey] = @{Name=$nu.Name;Domain=$domainName;Type='user';Groups=@();Delegations=@();Risks=@();IsServiceAccount=$nu.IsServiceAccount;IsDisabled=$nu.IsDisabled}
                    }
                    $PrincipalProfiles[$pKey].Groups += "$($grp.Name) via $($nu.Depth)-level nesting ($domainName)"
                }
            }
        } catch { }
    }
}
Write-Host "  [+] Nested chain paths: $($NestedChainPaths.Count)" -ForegroundColor $(if($NestedChainPaths.Count -gt 0){'Red'}else{'Green'})

# ==============================================================================
# PHASE 2: COLLECT DANGEROUS DELEGATIONS (ALL DOMAINS)
# ==============================================================================
Write-Host ""
Write-Host "  --- Phase 2: Dangerous Delegation Paths ---" -ForegroundColor Cyan

$DangerousRights = @('GenericAll','WriteDacl','WriteOwner','GenericWrite')
$SensitiveProperties = @('member','servicePrincipalName','msDS-AllowedToActOnBehalfOfOtherIdentity','msDS-KeyCredentialLink','userAccountControl','pwdLastSet')
$Tier0Patterns = @('Domain Controllers','Tier.?0','T0','Admin','Privileged','Enterprise')

foreach ($domainName in $allDomains) {
    $server = $null
    try {
        $domObj = Get-ADDomain -Identity $domainName -ErrorAction Stop
        $server = $domObj.PDCEmulator
        $domNetBIOS = $domObj.NetBIOSName
    } catch { continue }

    $ous = @()
    try { $ous = @(Get-ADOrganizationalUnit -Filter * -Server $server -Properties CanonicalName -ErrorAction Stop) } catch { continue }

    foreach ($ou in $ous) {
        $ouDN = $ou.DistinguishedName
        $ouObj = $null
        try { $ouObj = Get-ADObject -Identity $ouDN -Server $server -Properties nTSecurityDescriptor,CanonicalName -ErrorAction Stop } catch { continue }
        if (-not $ouObj.nTSecurityDescriptor) { continue }

        # Check if this is a Tier 0 OU
        $isTier0 = $false
        foreach ($tp in $Tier0Patterns) { if ($ouDN -match $tp) { $isTier0 = $true; break } }

        foreach ($ace in $ouObj.nTSecurityDescriptor.Access) {
            $identity = $ace.IdentityReference.Value
            if ([string]::IsNullOrWhiteSpace($identity)) { continue }

            # Resolve SIDs
            if ($identity -match '^S-1-') {
                try { $identity = (New-Object System.Security.Principal.SecurityIdentifier($identity)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
            }
            if (Test-BuiltIn $identity) { continue }
            if ($ace.IsInherited) { continue }
            if ($ace.AccessControlType -ne 'Allow') { continue }

            $rights = $ace.ActiveDirectoryRights.ToString()
            $objType = Resolve-GUID -g $ace.ObjectType.Guid
            $inhObjType = Resolve-GUID -g $ace.InheritedObjectType.Guid

            # Only track dangerous delegations
            $isDangerous = $false
            $pathType = ''
            $impact = ''
            $risk = 'Medium'

            # GenericAll / WriteDACL / WriteOwner
            if ($rights -match 'GenericAll') {
                $isDangerous = $true; $pathType = 'Full Control Delegation'; $risk = 'Critical'
                $impact = "Full control over all objects in this OU -- can create, delete, modify anything"
                if ($isTier0) { $impact = "CRITICAL: Full control over Tier 0 OU -- direct path to domain compromise" }
            }
            elseif ($rights -match 'WriteDacl') {
                $isDangerous = $true; $pathType = 'Permission Modification'; $risk = 'Critical'
                $impact = "Can modify permissions on this OU -- can grant self any access"
            }
            elseif ($rights -match 'WriteOwner') {
                $isDangerous = $true; $pathType = 'Ownership Takeover'; $risk = 'Critical'
                $impact = "Can take ownership then modify permissions -- escalation path"
            }
            elseif ($rights -match 'GenericWrite') {
                $isDangerous = $true; $pathType = 'Generic Write'; $risk = 'High'
                $impact = "Can modify most attributes on objects in this OU"
            }
            # Sensitive property writes
            elseif ($rights -match 'WriteProperty') {
                foreach ($sp in $SensitiveProperties) {
                    if ($objType -match $sp) {
                        $isDangerous = $true; $pathType = "Sensitive Write ($sp)"; $risk = 'High'
                        $impact = switch -Regex ($sp) {
                            'member' { "Can modify group membership -- add self to privileged groups" }
                            'servicePrincipalName' { "Can set SPN on accounts -- enables Kerberoasting attack" }
                            'msDS-AllowedToActOnBehalf' { "Can configure Resource-Based Constrained Delegation (RBCD) -- impersonation attack" }
                            'msDS-KeyCredentialLink' { "Can add Shadow Credentials -- authenticate as the target without knowing password" }
                            'userAccountControl' { "Can disable Kerberos pre-authentication -- enables AS-REP Roasting" }
                            'pwdLastSet' { "Can force password expiry -- social engineering for password reset" }
                            default { "Can write sensitive property: $sp" }
                        }
                        break
                    }
                }
            }
            # ExtendedRight on All (or replication)
            elseif ($rights -match 'ExtendedRight' -and ($objType -eq 'All' -or $objType -match 'Replicat')) {
                $isDangerous = $true; $pathType = 'Extended Rights'; $risk = 'High'
                $impact = if ($objType -match 'Replicat') { "DCSync attack -- can replicate all password hashes from AD" } else { "All extended rights including password reset on all objects" }
            }

            if (-not $isDangerous) { continue }
            if ($isTier0) { $risk = 'Critical' }

            $ouShort = $ouObj.CanonicalName
            $principalName = ($identity -split '\\')[-1]

            $AllPaths.Add([PSCustomObject]@{
                Domain=$domainName; PathType=$pathType; Principal=$principalName;
                PrincipalType='delegation'; IsServiceAccount=$false;
                IsDisabled=$false; Target="$ouShort"; Chain="$identity -> $pathType -> $ouShort";
                Impact=$impact; Risk=$risk; RiskReason="$pathType on $ouShort";
                Category='Delegation'
            })

            # Update principal profile
            $pKey = "$principalName@$domainName"
            if (-not $PrincipalProfiles.ContainsKey($pKey)) {
                $PrincipalProfiles[$pKey] = @{Name=$principalName;Domain=$domainName;Type='delegation';Groups=@();Delegations=@();Risks=@();IsServiceAccount=$false;IsDisabled=$false}
            }
            $PrincipalProfiles[$pKey].Delegations += "$pathType on $ouShort"
        }
    }
}
$delegPaths = @($AllPaths | Where-Object { $_.Category -eq 'Delegation' }).Count
Write-Host "  [+] Dangerous delegation paths: $delegPaths" -ForegroundColor Green

# ==============================================================================
# PHASE 2B: GPO ATTACK PATHS
# ==============================================================================
Write-Host ""
Write-Host "  --- Phase 2B: GPO Attack Paths ---" -ForegroundColor Cyan

$GPOPaths = [System.Collections.Generic.List[object]]::new()
foreach ($domainName in $allDomains) {
    try {
        $domObj = Get-ADDomain -Identity $domainName -ErrorAction Stop
        $server = $domObj.PDCEmulator

        $gpos = @(Get-GPO -All -Domain $domainName -Server $server -ErrorAction Stop)
        Write-Host "  [*] $domainName : $($gpos.Count) GPOs" -ForegroundColor White

        # Find GPOs linked to sensitive OUs
        $sensitiveOUs = @()
        try { $sensitiveOUs += @(Get-ADOrganizationalUnit -Filter * -Server $server -Properties gpLink,CanonicalName -ErrorAction Stop | Where-Object { $_.gpLink -and ($_.DistinguishedName -match 'Domain Controllers|Tier.?0|T0|Admin|Privileged') }) } catch { }
        # Also check domain root
        $domRoot = $null
        try { $domRoot = Get-ADObject -Identity $domObj.DistinguishedName -Server $server -Properties gpLink -ErrorAction Stop } catch { }

        $linkedGPOGuids = @{}
        foreach ($sou in $sensitiveOUs) {
            $links = [regex]::Matches($sou.gpLink, '\{([0-9a-fA-F-]+)\}')
            foreach ($lk in $links) { $linkedGPOGuids[$lk.Groups[1].Value.ToLower()] = $sou.CanonicalName }
        }
        if ($domRoot -and $domRoot.gpLink) {
            $links = [regex]::Matches($domRoot.gpLink, '\{([0-9a-fA-F-]+)\}')
            foreach ($lk in $links) { $linkedGPOGuids[$lk.Groups[1].Value.ToLower()] = $domainName + ' (Domain Root)' }
        }

        foreach ($gpo in $gpos) {
            $gpoId = $gpo.Id.Guid.ToLower()
            $linkedTo = if ($linkedGPOGuids.ContainsKey($gpoId)) { $linkedGPOGuids[$gpoId] } else { $null }

            # Check GPO permissions
            try {
                $gpoPerms = Get-GPPermission -Guid $gpo.Id -All -DomainName $domainName -Server $server -ErrorAction Stop
                foreach ($perm in $gpoPerms) {
                    if ($perm.Permission -in @('GpoEditDeleteModifySecurity','GpoEdit') -and $perm.Trustee.SidType -ne 'WellKnownGroup') {
                        $tName = $perm.Trustee.Name
                        if ($tName -match '^Domain Admins$|^Enterprise Admins$|^SYSTEM$') { continue }

                        $risk = 'High'
                        $impact = "Can modify GPO '$($gpo.DisplayName)' -- code execution on all computers where this GPO applies"
                        if ($linkedTo) { $risk = 'Critical'; $impact = "Can modify GPO '$($gpo.DisplayName)' linked to $linkedTo -- code execution on Tier 0 systems" }

                        $AllPaths.Add([PSCustomObject]@{
                            Domain=$domainName; PathType='GPO Edit'; Principal=$tName;
                            PrincipalType='gpo-editor'; IsServiceAccount=$false; IsDisabled=$false;
                            Target="GPO: $($gpo.DisplayName)"; Chain="$tName -> Edit GPO '$($gpo.DisplayName)' -> $(if($linkedTo){$linkedTo}else{'linked OUs'})";
                            Impact=$impact; Risk=$risk; RiskReason="Can edit GPO $(if($linkedTo){"linked to $linkedTo"}else{'(check linked OUs)'})";
                            Category='GPO'
                        })
                        $GPOPaths.Add([PSCustomObject]@{Domain=$domainName;GPO=$gpo.DisplayName;Editor=$tName;LinkedTo=$linkedTo;Risk=$risk})
                    }
                }
            } catch { }
        }
    } catch {
        Write-Host "  [i] GPO enumeration requires GroupPolicy module -- skipping $domainName" -ForegroundColor Gray
    }
}
Write-Host "  [+] GPO attack paths: $($GPOPaths.Count)" -ForegroundColor Green

# ==============================================================================
# PHASE 2C: KERBEROS DELEGATION ATTACK PATHS
# ==============================================================================
Write-Host ""
Write-Host "  --- Phase 2C: Kerberos Delegation ---" -ForegroundColor Cyan

$KerbDelegPaths = [System.Collections.Generic.List[object]]::new()
foreach ($domainName in $allDomains) {
    try {
        $domObj = Get-ADDomain -Identity $domainName -ErrorAction Stop
        $server = $domObj.PDCEmulator

        # Unconstrained delegation (computers and users, excluding DCs)
        $unconstrained = @(Get-ADObject -Filter { TrustedForDelegation -eq $true } -Server $server -Properties Name,objectClass,sAMAccountName,TrustedForDelegation,servicePrincipalName,Enabled,DistinguishedName -ErrorAction Stop)
        foreach ($obj in $unconstrained) {
            if ($obj.DistinguishedName -match 'OU=Domain Controllers,') { continue }
            $isUser = ($obj.objectClass -eq 'user')
            $risk = 'Critical'
            $impact = if ($isUser) { "Unconstrained delegation on USER account -- can capture TGT of ANY user who authenticates to services on this account" } else { "Unconstrained delegation on computer -- any user (including admins) who connects to this server will have their TGT cached and extractable" }

            $AllPaths.Add([PSCustomObject]@{
                Domain=$domainName; PathType='Unconstrained Delegation'; Principal=$obj.Name;
                PrincipalType=$obj.objectClass; IsServiceAccount=$isUser; IsDisabled=$false;
                Target='Any authenticating user TGT'; Chain="$($obj.Name) [Unconstrained Deleg] -> Capture ANY user TGT";
                Impact=$impact; Risk=$risk; RiskReason="Unconstrained delegation -- any admin who connects has TGT stolen";
                Category='Kerberos Delegation'
            })
            $KerbDelegPaths.Add([PSCustomObject]@{Domain=$domainName;Account=$obj.Name;Type='Unconstrained';ObjectClass=$obj.objectClass;DelegatesTo='ANY';Risk=$risk})
        }

        # Constrained delegation
        $constrained = @(Get-ADObject -Filter { msDS-AllowedToDelegateTo -like "*" } -Server $server -Properties Name,objectClass,sAMAccountName,'msDS-AllowedToDelegateTo',Enabled,TrustedToAuthForDelegation -ErrorAction Stop)
        foreach ($obj in $constrained) {
            $delegTargets = @($obj.'msDS-AllowedToDelegateTo')
            $hasProtocolTransition = [bool]$obj.TrustedToAuthForDelegation
            $risk = if ($hasProtocolTransition) { 'High' } else { 'Medium' }
            $targetStr = ($delegTargets | Select-Object -First 3) -join ', '
            if ($delegTargets.Count -gt 3) { $targetStr += " (+$($delegTargets.Count - 3) more)" }

            # Check if any targets are DCs or admin services
            $targetsDC = $false
            foreach ($t in $delegTargets) { if ($t -match 'ldap/|cifs/.*DC|HOST/.*DC') { $targetsDC = $true; $risk = 'Critical'; break } }

            $impact = "Constrained delegation to $($delegTargets.Count) services"
            if ($hasProtocolTransition) { $impact += " WITH protocol transition (S4U2Self) -- can impersonate ANY user to these services without their involvement" }
            if ($targetsDC) { $impact = "CRITICAL: Constrained delegation to DC services -- can impersonate Domain Admin to the DC" }

            $AllPaths.Add([PSCustomObject]@{
                Domain=$domainName; PathType=$(if($hasProtocolTransition){'Constrained Deleg + Protocol Transition'}else{'Constrained Delegation'});
                Principal=$obj.Name; PrincipalType=$obj.objectClass; IsServiceAccount=$true; IsDisabled=$false;
                Target=$targetStr; Chain="$($obj.Name) -> Impersonate users to -> $targetStr";
                Impact=$impact; Risk=$risk; RiskReason="Constrained delegation$(if($hasProtocolTransition){' with protocol transition'})$(if($targetsDC){' to DC services'})";
                Category='Kerberos Delegation'
            })
            $KerbDelegPaths.Add([PSCustomObject]@{Domain=$domainName;Account=$obj.Name;Type=$(if($hasProtocolTransition){'Constrained+S4U'}else{'Constrained'});ObjectClass=$obj.objectClass;DelegatesTo=$targetStr;Risk=$risk})
        }

        # RBCD (Resource-Based Constrained Delegation)
        $rbcd = @(Get-ADComputer -Filter { PrincipalsAllowedToDelegateToAccount -like "*" } -Server $server -Properties Name,PrincipalsAllowedToDelegateToAccount -ErrorAction SilentlyContinue)
        foreach ($obj in $rbcd) {
            $allowedPrincipals = @($obj.PrincipalsAllowedToDelegateToAccount | ForEach-Object { $_.Value })
            $risk = 'High'

            $AllPaths.Add([PSCustomObject]@{
                Domain=$domainName; PathType='RBCD (Resource-Based)'; Principal=($allowedPrincipals -join ', ');
                PrincipalType='computer'; IsServiceAccount=$false; IsDisabled=$false;
                Target=$obj.Name; Chain="$($allowedPrincipals -join ', ') -> RBCD -> impersonate users to $($obj.Name)";
                Impact="Resource-Based Constrained Delegation allows these principals to impersonate any user to $($obj.Name)";
                Risk=$risk; RiskReason="RBCD configured on $($obj.Name)";
                Category='Kerberos Delegation'
            })
            $KerbDelegPaths.Add([PSCustomObject]@{Domain=$domainName;Account=$obj.Name;Type='RBCD';ObjectClass='computer';DelegatesTo=($allowedPrincipals -join ', ');Risk=$risk})
        }
    } catch { }
}
Write-Host "  [+] Kerberos delegation paths: $($KerbDelegPaths.Count)" -ForegroundColor Green

# ==============================================================================
# PHASE 2D: DCSYNC-CAPABLE ACCOUNTS (DOMAIN ROOT ACL)
# ==============================================================================
Write-Host ""
Write-Host "  --- Phase 2D: DCSync-Capable Accounts ---" -ForegroundColor Cyan

$DCSyncPaths = [System.Collections.Generic.List[object]]::new()
$dcsyncRights = @('Replicating Directory Changes','Replicating Directory Changes All','Replicating Directory Changes In Filtered Set')

foreach ($domainName in $allDomains) {
    try {
        $domObj = Get-ADDomain -Identity $domainName -ErrorAction Stop
        $server = $domObj.PDCEmulator
        $domDN = $domObj.DistinguishedName

        $rootObj = Get-ADObject -Identity $domDN -Server $server -Properties nTSecurityDescriptor -ErrorAction Stop
        if (-not $rootObj.nTSecurityDescriptor) { continue }

        $principalDCSync = @{}
        foreach ($ace in $rootObj.nTSecurityDescriptor.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $identity = $ace.IdentityReference.Value
            if ($identity -match '^S-1-') {
                try { $identity = (New-Object System.Security.Principal.SecurityIdentifier($identity)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
            }
            if ($identity -match 'Domain Controllers|Enterprise Domain Controllers|SYSTEM|Administrators|Enterprise Admins|Domain Admins') { continue }
            if ($identity -match '^S-1-5-32-|^S-1-5-9|^S-1-5-18') { continue }

            $rights = $ace.ActiveDirectoryRights.ToString()
            if ($rights -notmatch 'ExtendedRight') { continue }
            $objType = Resolve-GUID -g $ace.ObjectType.Guid
            if ($objType -in $dcsyncRights) {
                if (-not $principalDCSync.ContainsKey($identity)) { $principalDCSync[$identity] = @() }
                $principalDCSync[$identity] += $objType
            }
        }

        foreach ($entry in $principalDCSync.GetEnumerator()) {
            $hasAll = ($entry.Value -contains 'Replicating Directory Changes' -and $entry.Value -contains 'Replicating Directory Changes All')
            $risk = if ($hasAll) { 'Critical' } else { 'High' }
            $principalName = ($entry.Key -split '\\')[-1]

            $AllPaths.Add([PSCustomObject]@{
                Domain=$domainName; PathType='DCSync'; Principal=$principalName;
                PrincipalType='dcsync'; IsServiceAccount=$false; IsDisabled=$false;
                Target="$domainName domain root"; Chain="$($entry.Key) -> DCSync -> Dump all password hashes from $domainName";
                Impact="$(if($hasAll){'FULL DCSync capability -- can replicate ALL password hashes from the domain including KRBTGT'}else{'Partial replication rights -- investigate if combined rights enable DCSync'})";
                Risk=$risk; RiskReason="Has $($entry.Value -join ' + ') on domain root";
                Category='DCSync'
            })
            $DCSyncPaths.Add([PSCustomObject]@{Domain=$domainName;Principal=$entry.Key;Rights=($entry.Value -join ' + ');FullDCSync=$hasAll;Risk=$risk})
        }
    } catch { }
}
Write-Host "  [+] DCSync-capable accounts: $($DCSyncPaths.Count)" -ForegroundColor Green

# ==============================================================================
# PHASE 2E: TRUST ATTACK PATHS
# ==============================================================================
Write-Host ""
Write-Host "  --- Phase 2E: Trust Analysis ---" -ForegroundColor Cyan

$TrustPaths = [System.Collections.Generic.List[object]]::new()
foreach ($domainName in $allDomains) {
    try {
        $domObj = Get-ADDomain -Identity $domainName -ErrorAction Stop
        $server = $domObj.PDCEmulator

        $trusts = @(Get-ADTrust -Filter * -Server $server -Properties Name,Direction,TrustType,ForestTransitive,SIDFilteringQuarantined,SIDFilteringForestAware,SelectiveAuthentication,TrustAttributes,TGTDelegation -ErrorAction Stop)

        foreach ($trust in $trusts) {
            $risks = @()
            $risk = 'Medium'

            # SID Filtering disabled = cross-domain SID injection
            if ($trust.SIDFilteringQuarantined -eq $false -and $trust.TrustType -eq 'External') {
                $risks += 'SID filtering DISABLED on external trust'
                $risk = 'Critical'
            }

            # SID History across forest trust without filtering
            if ($trust.ForestTransitive -and $trust.SIDFilteringForestAware -eq $false) {
                $risks += 'Forest trust without SID forest awareness filtering'
                $risk = 'High'
            }

            # No selective authentication = any user in trusted domain can access resources
            if ($trust.SelectiveAuthentication -eq $false -and $trust.Direction -in @('Inbound','BiDirectional')) {
                $risks += 'No selective authentication -- all users in trusted domain can access resources'
                if ($risk -ne 'Critical') { $risk = 'High' }
            }

            # TGT Delegation enabled
            if ($trust.TGTDelegation -eq $true) {
                $risks += 'TGT delegation enabled across trust -- enables unconstrained delegation abuse'
                $risk = 'Critical'
            }

            if ($risks.Count -eq 0) { continue }

            $dirStr = switch ($trust.Direction) { 0 {'Inbound'} 1 {'Outbound'} 2 {'BiDirectional'} default {$trust.Direction.ToString()} }
            $typeStr = if ($trust.ForestTransitive) { 'Forest' } else { $trust.TrustType.ToString() }

            $AllPaths.Add([PSCustomObject]@{
                Domain=$domainName; PathType="Trust: $typeStr ($dirStr)"; Principal=$trust.Name;
                PrincipalType='trust'; IsServiceAccount=$false; IsDisabled=$false;
                Target="$domainName"; Chain="$($trust.Name) [$dirStr $typeStr trust] -> $domainName";
                Impact=($risks -join ' | '); Risk=$risk; RiskReason=($risks -join '; ');
                Category='Trust'
            })
            $TrustPaths.Add([PSCustomObject]@{Domain=$domainName;TrustedDomain=$trust.Name;Direction=$dirStr;Type=$typeStr;Risks=($risks -join '; ');Risk=$risk;SIDFiltering=$trust.SIDFilteringQuarantined;SelectiveAuth=$trust.SelectiveAuthentication})
        }
    } catch { }
}
Write-Host "  [+] Trust attack paths: $($TrustPaths.Count)" -ForegroundColor Green

# ==============================================================================
# PHASE 2F: ADMINSDHOLDER + KERBEROASTABLE ADMINS
# ==============================================================================
Write-Host ""
Write-Host "  --- Phase 2F: AdminSDHolder & Kerberoastable Admins ---" -ForegroundColor Cyan

$AdminSDHolderAccts = [System.Collections.Generic.List[object]]::new()
$KerberoastableAdmins = [System.Collections.Generic.List[object]]::new()

foreach ($domainName in $allDomains) {
    try {
        $domObj = Get-ADDomain -Identity $domainName -ErrorAction Stop
        $server = $domObj.PDCEmulator

        # AdminSDHolder protected accounts (AdminCount=1)
        $adminCountUsers = @(Get-ADUser -Filter { AdminCount -eq 1 -and Enabled -eq $true } -Server $server -Properties AdminCount,MemberOf,servicePrincipalName -ErrorAction Stop)
        foreach ($u in $adminCountUsers) {
            $AdminSDHolderAccts.Add([PSCustomObject]@{Domain=$domainName;Account=$u.Name;SPN=if($u.servicePrincipalName){$true}else{$false};Groups=@($u.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ', '})

            # Kerberoastable admins: AdminCount=1 AND has SPN
            if ($u.servicePrincipalName -and @($u.servicePrincipalName).Count -gt 0) {
                $risk = 'Critical'
                $spns = @($u.servicePrincipalName) -join ', '
                $AllPaths.Add([PSCustomObject]@{
                    Domain=$domainName; PathType='Kerberoastable Admin'; Principal=$u.Name;
                    PrincipalType='user'; IsServiceAccount=$true; IsDisabled=$false;
                    Target='Offline Password Cracking'; Chain="$($u.Name) [SPN: $($spns | Select-Object -First 1)] -> Request TGS -> Crack Password Offline";
                    Impact="Admin account with SPN set -- ANY domain user can request a service ticket and crack the password offline. If password is weak, attacker gets admin access.";
                    Risk=$risk; RiskReason="Kerberoastable account with AdminCount=1 (protected by AdminSDHolder)";
                    Category='Kerberoast'
                })
                $KerberoastableAdmins.Add([PSCustomObject]@{Domain=$domainName;Account=$u.Name;SPN=($spns | Select-Object -First 1);Risk=$risk})
            }
        }
    } catch { }
}
Write-Host "  [+] AdminSDHolder accounts: $($AdminSDHolderAccts.Count), Kerberoastable admins: $($KerberoastableAdmins.Count)" -ForegroundColor Green

# ==============================================================================
# PHASE 2G: AS-REP ROAST, SID HISTORY, STALE ADMINS, KRBTGT, MAQ
# ==============================================================================
Write-Host ""
Write-Host "  --- Phase 2G: Identity Risk Indicators ---" -ForegroundColor Cyan

$ASREPRoastable = [System.Collections.Generic.List[object]]::new()
$SIDHistoryAccts = [System.Collections.Generic.List[object]]::new()
$StaleAdmins = [System.Collections.Generic.List[object]]::new()
$KRBTGTInfo = [System.Collections.Generic.List[object]]::new()
$MAQInfo = [System.Collections.Generic.List[object]]::new()

foreach ($domainName in $allDomains) {
    try {
        $domObj = Get-ADDomain -Identity $domainName -ErrorAction Stop
        $server = $domObj.PDCEmulator

        # --- AS-REP Roastable accounts ---
        try {
            $asrepUsers = @(Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true } -Server $server -Properties DoesNotRequirePreAuth,AdminCount,MemberOf,servicePrincipalName -ErrorAction Stop)
            foreach ($u in $asrepUsers) {
                $isAdmin = ($u.AdminCount -eq 1)
                $risk = if ($isAdmin) { 'Critical' } else { 'High' }
                $groups = @($u.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ', '

                $ASREPRoastable.Add([PSCustomObject]@{Domain=$domainName;Account=$u.Name;IsAdmin=$isAdmin;Groups=$groups;Risk=$risk})

                $AllPaths.Add([PSCustomObject]@{
                    Domain=$domainName; PathType='AS-REP Roastable'; Principal=$u.Name;
                    PrincipalType='user'; IsServiceAccount=$false; IsDisabled=$false;
                    Target='Offline Password Cracking'; Chain="$($u.Name) [DONT_REQ_PREAUTH] -> Request AS-REP -> Crack Password Offline";
                    Impact="$(if($isAdmin){'CRITICAL: Admin account'}else{'Account'}) with Kerberos pre-auth disabled -- ANY user can request and crack the password offline without any authentication";
                    Risk=$risk; RiskReason="AS-REP Roastable$(if($isAdmin){' ADMIN'}) account -- pre-authentication disabled";
                    Category='AS-REP Roast'
                })
            }
        } catch { }

        # --- SID History ---
        try {
            $sidHistUsers = @(Get-ADUser -Filter { SIDHistory -like "*" } -Server $server -Properties SIDHistory,Enabled,AdminCount,MemberOf -ErrorAction Stop)
            foreach ($u in $sidHistUsers) {
                if (-not $u.Enabled) { continue }
                $sidHistEntries = @($u.SIDHistory | ForEach-Object { $_.Value })
                $risk = 'High'
                # Check if any SID in history matches a known DA/EA pattern (-500 or admin RID)
                foreach ($sh in $sidHistEntries) {
                    if ($sh -match '-500$|-512$|-519$|-544$') { $risk = 'Critical'; break }
                }

                $SIDHistoryAccts.Add([PSCustomObject]@{Domain=$domainName;Account=$u.Name;SIDHistoryCount=$sidHistEntries.Count;SIDHistory=($sidHistEntries | Select-Object -First 3) -join ', ';IsAdmin=($u.AdminCount -eq 1);Risk=$risk})

                $AllPaths.Add([PSCustomObject]@{
                    Domain=$domainName; PathType='SID History'; Principal=$u.Name;
                    PrincipalType='user'; IsServiceAccount=$false; IsDisabled=$false;
                    Target="$($sidHistEntries.Count) historical SIDs"; Chain="$($u.Name) has $($sidHistEntries.Count) SIDs in SIDHistory -> Can impersonate those identities";
                    Impact="Account carries $($sidHistEntries.Count) historical SIDs. If any map to privileged accounts from other domains, this user effectively HAS those privileges. $(if($risk -eq 'Critical'){'Contains well-known admin SID patterns.'})";
                    Risk=$risk; RiskReason="SID History with $($sidHistEntries.Count) entries$(if($risk -eq 'Critical'){' including admin SID patterns'})";
                    Category='SID History'
                })
            }
        } catch { }

        # --- Stale Admin Accounts (90+ days, enabled, in admin groups) ---
        try {
            $staleDate = (Get-Date).AddDays(-90)
            $staleUsers = @(Get-ADUser -Filter { AdminCount -eq 1 -and Enabled -eq $true -and LastLogonDate -lt $staleDate } -Server $server -Properties AdminCount,LastLogonDate,MemberOf,PasswordLastSet -ErrorAction Stop)
            foreach ($u in $staleUsers) {
                $daysSinceLogon = if ($u.LastLogonDate) { [math]::Round(((Get-Date) - $u.LastLogonDate).TotalDays) } else { 999 }
                $daysSincePwd = if ($u.PasswordLastSet) { [math]::Round(((Get-Date) - $u.PasswordLastSet).TotalDays) } else { 999 }
                $groups = @($u.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ', '
                $risk = if ($daysSinceLogon -gt 365) { 'Critical' } else { 'High' }

                $StaleAdmins.Add([PSCustomObject]@{Domain=$domainName;Account=$u.Name;DaysSinceLogon=$daysSinceLogon;DaysSincePwdChange=$daysSincePwd;Groups=$groups;Risk=$risk})

                $AllPaths.Add([PSCustomObject]@{
                    Domain=$domainName; PathType='Stale Admin Account'; Principal=$u.Name;
                    PrincipalType='user'; IsServiceAccount=$false; IsDisabled=$false;
                    Target='Unmonitored Admin Access'; Chain="$($u.Name) [Last logon: $daysSinceLogon days ago, Pwd: $daysSincePwd days ago] -> Still in admin groups";
                    Impact="Admin account inactive for $daysSinceLogon days but still enabled with admin privileges. Password is $daysSincePwd days old. Unmonitored accounts are prime targets for compromise.";
                    Risk=$risk; RiskReason="Admin account inactive $daysSinceLogon days -- password $daysSincePwd days old";
                    Category='Stale Admin'
                })
            }
        } catch { }

        # --- KRBTGT Password Age ---
        try {
            $krbtgt = Get-ADUser 'krbtgt' -Server $server -Properties PasswordLastSet -ErrorAction Stop
            $krbtgtAge = if ($krbtgt.PasswordLastSet) { [math]::Round(((Get-Date) - $krbtgt.PasswordLastSet).TotalDays) } else { 9999 }
            $risk = if ($krbtgtAge -gt 365) { 'Critical' } elseif ($krbtgtAge -gt 180) { 'High' } else { 'Medium' }

            $KRBTGTInfo.Add([PSCustomObject]@{Domain=$domainName;PasswordLastSet=$krbtgt.PasswordLastSet;AgeDays=$krbtgtAge;Risk=$risk})

            if ($krbtgtAge -gt 180) {
                $AllPaths.Add([PSCustomObject]@{
                    Domain=$domainName; PathType='KRBTGT Stale Password'; Principal='krbtgt';
                    PrincipalType='system'; IsServiceAccount=$false; IsDisabled=$false;
                    Target='Golden Ticket Persistence'; Chain="krbtgt password is $krbtgtAge days old -> Any past DCSync = still-valid Golden Tickets";
                    Impact="KRBTGT password has not been changed in $krbtgtAge days. Any attacker who obtained the KRBTGT hash (via DCSync or NTDS.dit extraction) at ANY point in the last $krbtgtAge days can create Golden Tickets that are STILL VALID. Microsoft recommends rotating every 180 days.";
                    Risk=$risk; RiskReason="KRBTGT password age: $krbtgtAge days (recommend rotate every 180 days)";
                    Category='KRBTGT'
                })
            }
        } catch { }

        # --- Machine Account Quota (MAQ) ---
        try {
            $maq = (Get-ADObject $domObj.DistinguishedName -Server $server -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop).'ms-DS-MachineAccountQuota'
            if ($null -eq $maq) { $maq = 10 }  # Default is 10
            $risk = if ($maq -gt 0) { 'High' } else { 'Low' }

            $MAQInfo.Add([PSCustomObject]@{Domain=$domainName;Quota=$maq;Risk=$risk})

            if ($maq -gt 0) {
                $AllPaths.Add([PSCustomObject]@{
                    Domain=$domainName; PathType='Machine Account Quota'; Principal='Any Domain User';
                    PrincipalType='policy'; IsServiceAccount=$false; IsDisabled=$false;
                    Target="Create up to $maq computer accounts"; Chain="Any user -> Create $maq computer accounts -> Use for RBCD attacks";
                    Impact="Any domain user can create up to $maq computer accounts. These machine accounts can be used as pivot points for Resource-Based Constrained Delegation (RBCD) attacks to impersonate admin users.";
                    Risk=$risk; RiskReason="MachineAccountQuota is $maq (should be 0)";
                    Category='MAQ'
                })
            }
        } catch { }
    } catch { }
}
Write-Host "  [+] AS-REP Roastable: $($ASREPRoastable.Count), SID History: $($SIDHistoryAccts.Count), Stale Admins: $($StaleAdmins.Count)" -ForegroundColor Green
Write-Host "  [+] KRBTGT checked: $($KRBTGTInfo.Count) domains, MAQ checked: $($MAQInfo.Count) domains" -ForegroundColor Green

# ==============================================================================
# PHASE 3: IDENTIFY SPECIFIC ATTACK SCENARIOS
# ==============================================================================
Write-Host ""
Write-Host "  --- Phase 3: Attack Scenario Analysis ---" -ForegroundColor Cyan

$AttackScenarios = [System.Collections.Generic.List[object]]::new()

# Scenario 1: Service accounts in admin groups
$svcInAdmin = @($AllPaths | Where-Object { $_.IsServiceAccount -and $_.Category -eq 'Group Membership' })
if ($svcInAdmin.Count -gt 0) {
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario='Service Account with Admin Privileges'; Severity='Critical';
        Count=$svcInAdmin.Count;
        Description='Service accounts in privileged groups. Credentials are stored on application servers and can be extracted by attackers.';
        AttackSteps='1. Attacker compromises application server running the service|2. Extracts service account credentials from memory (Mimikatz/lsass dump)|3. Uses credentials to authenticate as the service account|4. Service account is in admin group -- attacker now has admin access';
        Affected=($svcInAdmin | ForEach-Object { "$($_.Principal) in $($_.Target) ($($_.Domain))" }) -join '|';
        Remediation='Remove service accounts from privileged groups. Use gMSA instead. Apply least-privilege delegation.'
    })
}

# Scenario 2: Disabled accounts in admin groups
$disabledInAdmin = @($AllPaths | Where-Object { $_.IsDisabled -and $_.Category -eq 'Group Membership' })
if ($disabledInAdmin.Count -gt 0) {
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario='Disabled Accounts in Privileged Groups'; Severity='High';
        Count=$disabledInAdmin.Count;
        Description='Disabled accounts still in privileged groups. If re-enabled (accidentally or by attacker), they immediately gain admin access.';
        AttackSteps='1. Attacker identifies disabled account in admin group|2. Re-enables the account (if they have Account Operator or similar access)|3. Account instantly has admin privileges|4. Attacker uses account for persistence';
        Affected=($disabledInAdmin | ForEach-Object { "$($_.Principal) in $($_.Target) ($($_.Domain))" }) -join '|';
        Remediation='Remove disabled accounts from ALL privileged groups immediately.'
    })
}

# Scenario 3: Delegation to Tier 0
$tier0Del = @($AllPaths | Where-Object { $_.Category -eq 'Delegation' -and $_.Risk -eq 'Critical' -and $_.Target -match 'Tier.?0|T0|Admin|Domain Controller' })
if ($tier0Del.Count -gt 0) {
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario='Non-Admin Delegation to Tier 0 Objects'; Severity='Critical';
        Count=$tier0Del.Count;
        Description='Non-admin principals have dangerous delegations on Tier 0 OUs (Domain Controllers, admin accounts, privileged access). This is a direct escalation path.';
        AttackSteps='1. Attacker compromises a delegated principal (e.g., helpdesk account)|2. Uses delegation (GenericAll/WriteDACL) on Tier 0 OU|3. Creates admin account or modifies existing admin|4. Full domain/forest compromise';
        Affected=($tier0Del | ForEach-Object { "$($_.Principal) -> $($_.PathType) on $($_.Target)" }) -join '|';
        Remediation='Remove all non-admin delegations from Tier 0 OUs. Only Domain Admins should have access to Tier 0.'
    })
}

# Scenario 4: WriteDACL/WriteOwner anywhere
$daclOwner = @($AllPaths | Where-Object { $_.PathType -match 'Permission Modification|Ownership Takeover' })
if ($daclOwner.Count -gt 0) {
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario='Permission Escalation via WriteDACL/WriteOwner'; Severity='Critical';
        Count=$daclOwner.Count;
        Description='Principals with WriteDACL or WriteOwner can grant themselves any permission, including Full Control. This is equivalent to having Full Control.';
        AttackSteps='1. Attacker compromises account with WriteDACL or WriteOwner|2. Modifies DACL to grant self GenericAll|3. Now has full control over the target OU and all objects within|4. Can escalate to domain admin if OU contains privileged accounts';
        Affected=($daclOwner | ForEach-Object { "$($_.Principal) -> $($_.PathType) on $($_.Target)" }) -join '|';
        Remediation='Remove WriteDACL and WriteOwner delegations. Use specific property-level permissions instead.'
    })
}

# Scenario 5: Shadow Credentials / RBCD / Kerberoasting paths
$credPaths = @($AllPaths | Where-Object { $_.PathType -match 'Sensitive Write' })
if ($credPaths.Count -gt 0) {
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario='Credential Attack Paths (Shadow Creds / RBCD / Kerberoast)'; Severity='High';
        Count=$credPaths.Count;
        Description='Principals can write sensitive properties that enable credential-based attacks: Shadow Credentials, Resource-Based Constrained Delegation, Kerberoasting, or AS-REP Roasting.';
        AttackSteps='1. Attacker compromises account with WriteProperty on sensitive attribute|2. Sets msDS-KeyCredentialLink (Shadow Credentials) or msDS-AllowedToActOnBehalf (RBCD) or servicePrincipalName (Kerberoasting)|3. Uses the modified attribute to authenticate as the target or crack their password|4. Lateral movement or privilege escalation';
        Affected=($credPaths | ForEach-Object { "$($_.Principal) -> $($_.PathType)" }) -join '|';
        Remediation='Remove WriteProperty on sensitive attributes. Monitor changes to these attributes with audit logging.'
    })
}

# Scenario 6: Excessive admin count
foreach ($domainName in $allDomains) {
    $daKey = "Domain Admins@$domainName"
    if ($GroupMemberMap.ContainsKey($daKey) -and $GroupMemberMap[$daKey].Effective -gt 5) {
        $AttackScenarios.Add([PSCustomObject]@{
            Scenario="Excessive Domain Admins ($domainName)"; Severity='High';
            Count=$GroupMemberMap[$daKey].Effective;
            Description="$($GroupMemberMap[$daKey].Effective) effective Domain Admins in $domainName. Microsoft recommends 2-5. Each additional admin is an additional attack surface.";
            AttackSteps='1. More admin accounts = more targets for credential theft|2. Attacker only needs to compromise ONE admin account|3. Single compromised admin = full domain control';
            Affected="$($GroupMemberMap[$daKey].Effective) effective members in Domain Admins ($domainName)";
            Remediation='Reduce Domain Admins to 2-5 members. Use delegated permissions for day-to-day tasks.'
        })
    }
}

# Scenario 7: Groups that should be empty
$shouldBeEmpty = @('Account Operators','Server Operators','Print Operators','Backup Operators')
foreach ($domainName in $allDomains) {
    foreach ($grpName in $shouldBeEmpty) {
        $key = "$grpName@$domainName"
        if ($GroupMemberMap.ContainsKey($key) -and $GroupMemberMap[$key].Direct -gt 0) {
            $AttackScenarios.Add([PSCustomObject]@{
                Scenario="Misused Built-In Group: $grpName ($domainName)"; Severity='Critical';
                Count=$GroupMemberMap[$key].Direct;
                Description="$grpName has $($GroupMemberMap[$key].Direct) members but should be EMPTY. This is a legacy operator group with dangerous DC-level privileges.";
                AttackSteps="1. $grpName members can log on to domain controllers|2. Can access sensitive files, services, or load drivers|3. Attacker targets these accounts for DC access|4. DC compromise leads to full domain compromise";
                Affected="$($GroupMemberMap[$key].Direct) members in $grpName ($domainName)";
                Remediation="Remove ALL members from $grpName. This group should be empty in modern AD environments."
            })
        }
    }
}

Write-Host "  [+] Attack scenarios identified: $($AttackScenarios.Count)" -ForegroundColor $(if($AttackScenarios.Count -gt 0){'Red'}else{'Green'})

# --- Additional scenarios from new phases ---

# Scenario: GPO attack paths on sensitive OUs
$gpoTier0 = @($AllPaths | Where-Object { $_.Category -eq 'GPO' -and $_.Risk -eq 'Critical' })
if ($gpoTier0.Count -gt 0) {
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario='GPO Modification on Tier 0 Systems'; Severity='Critical';
        Count=$gpoTier0.Count;
        Description='Non-admin principals can edit GPOs linked to Domain Controllers or Tier 0 OUs. GPO modification = arbitrary code execution on every system in scope.';
        AttackSteps='1. Attacker compromises account with GPO edit rights|2. Modifies GPO to add a scheduled task or startup script|3. Script runs on all computers where GPO applies (including DCs)|4. Immediate code execution as SYSTEM on domain controllers';
        Affected=($gpoTier0 | ForEach-Object { "$($_.Principal) -> Edit $($_.Target)" }) -join '|';
        Remediation='Remove non-admin GPO edit permissions. Only Domain Admins and Group Policy Creator Owners should edit GPOs linked to Tier 0.'
    })
}

# Scenario: Unconstrained delegation
$unconstr = @($AllPaths | Where-Object { $_.PathType -eq 'Unconstrained Delegation' })
if ($unconstr.Count -gt 0) {
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario='Unconstrained Kerberos Delegation'; Severity='Critical';
        Count=$unconstr.Count;
        Description='Servers or accounts with unconstrained delegation cache the TGT of every user who authenticates to them. If an admin connects, their TGT can be extracted and reused.';
        AttackSteps='1. Attacker compromises server with unconstrained delegation|2. Coerces a Domain Admin to authenticate (e.g., via print spooler abuse or PetitPotam)|3. Admin TGT is cached on the compromised server|4. Attacker extracts TGT and uses it to impersonate the admin';
        Affected=($unconstr | ForEach-Object { "$($_.Principal) ($($_.Domain))" }) -join '|';
        Remediation='Remove unconstrained delegation from all servers and accounts. Use constrained delegation or RBCD instead. Add admin accounts to Protected Users group.'
    })
}

# Scenario: DCSync-capable non-default accounts
if ($DCSyncPaths.Count -gt 0) {
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario='Non-Default DCSync-Capable Accounts'; Severity='Critical';
        Count=$DCSyncPaths.Count;
        Description='Non-default principals have Replicating Directory Changes rights on the domain root. This enables the DCSync attack -- replicate all password hashes including KRBTGT.';
        AttackSteps='1. Attacker compromises account with replication rights|2. Runs DCSync (e.g., Mimikatz lsadump::dcsync)|3. Retrieves NTLM hash of KRBTGT account|4. Creates Golden Ticket -- unlimited forest access with no expiry';
        Affected=($DCSyncPaths | ForEach-Object { "$($_.Principal) ($($_.Domain)) -- $($_.Rights)" }) -join '|';
        Remediation='Remove Replicating Directory Changes rights from non-default accounts. Only Domain Controllers, Enterprise Admins, and Domain Admins should have these rights.'
    })
}

# Scenario: Trust weaknesses
$trustRisks = @($AllPaths | Where-Object { $_.Category -eq 'Trust' -and $_.Risk -in @('Critical','High') })
if ($trustRisks.Count -gt 0) {
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario='Trust Security Weaknesses'; Severity=$(if(@($trustRisks|Where-Object{$_.Risk -eq 'Critical'}).Count -gt 0){'Critical'}else{'High'});
        Count=$trustRisks.Count;
        Description='Domain or forest trusts with security weaknesses that enable cross-domain/forest privilege escalation. Includes disabled SID filtering, missing selective authentication, or TGT delegation.';
        AttackSteps='1. Attacker compromises account in trusted domain|2. Exploits trust weakness (SID injection, TGT delegation, or unrestricted access)|3. Creates tickets with elevated SIDs from trusting domain|4. Gains admin access across trust boundary';
        Affected=($trustRisks | ForEach-Object { "$($_.Principal) <-> $($_.Domain): $($_.RiskReason)" }) -join '|';
        Remediation='Enable SID filtering on all external trusts. Enable selective authentication on forest trusts. Disable TGT delegation across trusts.'
    })
}

# Scenario: Kerberoastable admin accounts
if ($KerberoastableAdmins.Count -gt 0) {
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario='Kerberoastable Privileged Accounts'; Severity='Critical';
        Count=$KerberoastableAdmins.Count;
        Description='Admin accounts (AdminCount=1) with SPNs set. ANY domain user can request a service ticket for these accounts and crack the password offline. No special privileges needed.';
        AttackSteps='1. ANY domain user requests TGS for the admin accounts SPN|2. Service ticket is encrypted with the accounts password hash|3. Attacker cracks the ticket offline (hashcat/john) -- no failed logon events|4. If password is cracked, attacker has admin credentials';
        Affected=($KerberoastableAdmins | ForEach-Object { "$($_.Account) ($($_.Domain)) -- SPN: $($_.SPN)" }) -join '|';
        Remediation='Remove unnecessary SPNs from admin accounts. Use gMSA for service accounts. Ensure 25+ character passwords on accounts with SPNs.'
    })
}

# Scenario: Hidden nested admin accounts
if ($NestedChainPaths.Count -gt 0) {
    $maxDepth = ($NestedChainPaths | Measure-Object -Property Depth -Maximum).Maximum
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario="Hidden Admins via Nested Group Chains (up to $maxDepth levels deep)"; Severity='Critical';
        Count=$NestedChainPaths.Count;
        Description="Users who are effectively domain/enterprise admins but hidden behind $maxDepth levels of group nesting. Standard tools like ADUC only show direct members. These hidden admins are invisible to most audits.";
        AttackSteps="1. Attacker identifies deeply nested group chain using BloodHound or similar|2. Compromises the hidden user account (lower profile = less monitored)|3. User is effectively admin through group nesting|4. Attacker has full admin access while appearing as a normal user";
        Affected=($NestedChainPaths | ForEach-Object { "$($_.User) ($($_.Domain)) -- $($_.Chain)" }) -join '|';
        Remediation='Flatten group nesting. Remove unnecessary intermediate groups. Ensure all admin access paths are visible and documented. Maximum recommended nesting depth is 2.'
    })
}

# Scenario: AS-REP Roastable accounts
if ($ASREPRoastable.Count -gt 0) {
    $asrepAdmins = @($ASREPRoastable | Where-Object { $_.IsAdmin })
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario='AS-REP Roastable Accounts'; Severity=$(if($asrepAdmins.Count -gt 0){'Critical'}else{'High'});
        Count=$ASREPRoastable.Count;
        Description="$($ASREPRoastable.Count) accounts with Kerberos pre-authentication disabled. ANY user (even anonymous in some configs) can request an AS-REP and crack the password offline. No special privileges needed.$(if($asrepAdmins.Count -gt 0){" $($asrepAdmins.Count) of these are admin accounts."})";
        AttackSteps='1. ANY domain user identifies accounts with DONT_REQ_PREAUTH|2. Requests AS-REP for the target account (no authentication needed)|3. AS-REP is encrypted with the accounts password hash|4. Attacker cracks the hash offline -- no failed logon events generated';
        Affected=($ASREPRoastable | ForEach-Object { "$($_.Account) ($($_.Domain))$(if($_.IsAdmin){' [ADMIN]'})" }) -join '|';
        Remediation='Enable Kerberos pre-authentication on all accounts (uncheck DONT_REQ_PREAUTH). Enforce strong passwords (25+ chars) if pre-auth must be disabled.'
    })
}

# Scenario: SID History abuse
if ($SIDHistoryAccts.Count -gt 0) {
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario='SID History Privilege Escalation'; Severity=$(if(@($SIDHistoryAccts | Where-Object { $_.Risk -eq 'Critical' }).Count -gt 0){'Critical'}else{'High'});
        Count=$SIDHistoryAccts.Count;
        Description="$($SIDHistoryAccts.Count) enabled accounts carry SID History entries from other domains. These historical SIDs are included in the users Kerberos ticket and grant access as if the user IS the original account. If any SID maps to a privileged account, this is a hidden admin path.";
        AttackSteps='1. Attacker identifies user with SIDHistory containing privileged SIDs|2. Authenticates as that user (or compromises their account)|3. Kerberos ticket includes historical SIDs automatically|4. User gains access equivalent to the original privileged account';
        Affected=($SIDHistoryAccts | ForEach-Object { "$($_.Account) ($($_.Domain)) -- $($_.SIDHistoryCount) historical SIDs" }) -join '|';
        Remediation='Remove SID History after migration is complete: Get-ADUser -Properties SIDHistory | Set-ADUser -Remove @{SIDHistory=@()}. SID History should be temporary, not permanent.'
    })
}

# Scenario: Stale admin accounts
if ($StaleAdmins.Count -gt 0) {
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario='Stale Privileged Accounts'; Severity=$(if(@($StaleAdmins | Where-Object { $_.DaysSinceLogon -gt 365 }).Count -gt 0){'Critical'}else{'High'});
        Count=$StaleAdmins.Count;
        Description="$($StaleAdmins.Count) admin accounts (AdminCount=1) have not logged in for 90+ days but remain enabled with admin privileges. These forgotten accounts are prime targets -- they are rarely monitored and may have weak or unchanged passwords.";
        AttackSteps='1. Attacker identifies stale admin accounts (LDAP query for AdminCount + LastLogon)|2. Attempts password spray or credential stuffing against these accounts|3. Stale accounts are less likely to trigger alerts (no active user monitoring)|4. Compromised stale admin = full admin access with low detection risk';
        Affected=($StaleAdmins | ForEach-Object { "$($_.Account) ($($_.Domain)) -- inactive $($_.DaysSinceLogon) days, password $($_.DaysSincePwdChange) days old" }) -join '|';
        Remediation='Disable or remove stale admin accounts from privileged groups. Implement a 90-day inactive admin review process. Require regular re-certification of admin access.'
    })
}

# Scenario: KRBTGT password age
$staleKrbtgt = @($KRBTGTInfo | Where-Object { $_.AgeDays -gt 180 })
if ($staleKrbtgt.Count -gt 0) {
    $maxAge = ($staleKrbtgt | Measure-Object -Property AgeDays -Maximum).Maximum
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario='KRBTGT Password Not Rotated'; Severity=$(if($maxAge -gt 365){'Critical'}else{'High'});
        Count=$staleKrbtgt.Count;
        Description="KRBTGT password has not been changed in up to $maxAge days across $($staleKrbtgt.Count) domains. Any attacker who obtained the KRBTGT hash at ANY point can create Golden Tickets that are still valid. Golden Tickets grant unlimited access to the entire domain with no expiry.";
        AttackSteps="1. Attacker previously obtained KRBTGT hash (DCSync, NTDS.dit theft, or backup)|2. Creates a Golden Ticket (valid for up to $maxAge days since last KRBTGT reset)|3. Golden Ticket grants Domain Admin access to any resource|4. No authentication events are generated -- completely invisible";
        Affected=($staleKrbtgt | ForEach-Object { "$($_.Domain) -- KRBTGT password age: $($_.AgeDays) days (last set: $($_.PasswordLastSet))" }) -join '|';
        Remediation='Rotate the KRBTGT password TWICE (to invalidate all outstanding tickets). First rotation invalidates new tickets, second rotation invalidates remaining old tickets. Wait 12-24 hours between rotations. Then rotate every 180 days.'
    })
}

# Scenario: Machine Account Quota
$maqRisky = @($MAQInfo | Where-Object { $_.Quota -gt 0 })
if ($maqRisky.Count -gt 0) {
    $AttackScenarios.Add([PSCustomObject]@{
        Scenario='Machine Account Quota Enables RBCD Attacks'; Severity='High';
        Count=$maqRisky.Count;
        Description="$($maqRisky.Count) domains allow regular users to create computer accounts (MachineAccountQuota > 0, default is 10). Any user can create machine accounts and use them as pivot points for RBCD attacks to impersonate admin users on target systems.";
        AttackSteps='1. ANY domain user creates a computer account (allowed by MachineAccountQuota)|2. Attacker uses the machine account to configure RBCD on a target (if they have write access to msDS-AllowedToActOnBehalfOfOtherIdentity)|3. Impersonates any user (including Domain Admin) to the target service|4. Gains admin access to the target system';
        Affected=($maqRisky | ForEach-Object { "$($_.Domain) -- MachineAccountQuota = $($_.Quota)" }) -join '|';
        Remediation='Set MachineAccountQuota to 0: Set-ADDomain -Identity <domain> -Replace @{"ms-DS-MachineAccountQuota"="0"}. Pre-stage computer accounts instead of allowing users to create them.'
    })
}

# ==============================================================================
# PHASE 4: BUILD REPORT
# ==============================================================================
Write-Host ""
Write-Host "  [*] Building report ..." -ForegroundColor Yellow

$TotalPaths = $AllPaths.Count
$CriticalPaths = @($AllPaths | Where-Object { $_.Risk -eq 'Critical' }).Count
$HighPaths = @($AllPaths | Where-Object { $_.Risk -eq 'High' }).Count
$MediumPaths = @($AllPaths | Where-Object { $_.Risk -eq 'Medium' }).Count
$GroupPaths = @($AllPaths | Where-Object { $_.Category -eq 'Group Membership' }).Count
$DelegPaths = @($AllPaths | Where-Object { $_.Category -eq 'Delegation' }).Count
$GPOPathCount = @($AllPaths | Where-Object { $_.Category -eq 'GPO' }).Count
$KerbPathCount = @($AllPaths | Where-Object { $_.Category -eq 'Kerberos Delegation' }).Count
$DCSyncCount = @($AllPaths | Where-Object { $_.Category -eq 'DCSync' }).Count
$TrustPathCount = @($AllPaths | Where-Object { $_.Category -eq 'Trust' }).Count
$KerberoastCount = @($AllPaths | Where-Object { $_.Category -eq 'Kerberoast' }).Count
$NestedChainCount = @($AllPaths | Where-Object { $_.Category -eq 'Nested Chain' }).Count
$ASREPCount = @($AllPaths | Where-Object { $_.Category -eq 'AS-REP Roast' }).Count
$SIDHistCount = @($AllPaths | Where-Object { $_.Category -eq 'SID History' }).Count
$StaleAdminCount = @($AllPaths | Where-Object { $_.Category -eq 'Stale Admin' }).Count
$KRBTGTCount = @($AllPaths | Where-Object { $_.Category -eq 'KRBTGT' }).Count
$MAQCount = @($AllPaths | Where-Object { $_.Category -eq 'MAQ' }).Count

# Build principal risk profiles for top principals
$TopPrincipals = @()
foreach ($entry in ($PrincipalProfiles.GetEnumerator() | Sort-Object { @($_.Value.Groups).Count + @($_.Value.Delegations).Count } -Descending | Select-Object -First 25)) {
    $p = $entry.Value
    $totalAccess = @($p.Groups).Count + @($p.Delegations).Count
    $maxRisk = 'Low'
    if (@($p.Groups | Where-Object { $_ -match 'Enterprise Admins|Schema Admins' }).Count -gt 0) { $maxRisk = 'Critical' }
    elseif (@($p.Groups).Count -gt 0) { $maxRisk = 'High' }
    elseif (@($p.Delegations | Where-Object { $_ -match 'Full Control|WriteDacl|WriteOwner' }).Count -gt 0) { $maxRisk = 'Critical' }
    elseif (@($p.Delegations).Count -gt 0) { $maxRisk = 'Medium' }
    if ($p.IsServiceAccount) { $maxRisk = 'Critical' }

    $TopPrincipals += [PSCustomObject]@{
        Principal=$p.Name; Domain=$p.Domain; Type=$p.Type;
        PrivGroups=@($p.Groups).Count; Delegations=@($p.Delegations).Count;
        TotalAccess=$totalAccess; IsServiceAccount=$p.IsServiceAccount;
        IsDisabled=$p.IsDisabled; Risk=$maxRisk;
        GroupList=(@($p.Groups) | Select-Object -First 5) -join ', ';
        DelegationList=(@($p.Delegations) | Select-Object -First 5) -join ', '
    }
}

# Build HTML tables
function Build-Table {
    param($Data, [string[]]$Props, [int]$Limit=500)
    if (-not $Data -or @($Data).Count -eq 0) { return '<p class="empty-note">No data found.</p>' }
    $rows = @($Data) | Select-Object -First $Limit
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<div class="table-wrap"><table><thead><tr>')
    foreach ($p in $Props) { [void]$sb.Append("<th>$(HtmlEncode $p)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($row in $rows) {
        [void]$sb.Append('<tr>')
        foreach ($p in $Props) {
            $val = $row.$p
            if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) { $val = ($val | ForEach-Object { [string]$_ }) -join ", " }
            if ($p -eq 'Risk' -or $p -eq 'Severity') {
                $color = switch ($val) { 'Critical' { '#f87171' } 'High' { '#fb923c' } 'Medium' { '#fbbf24' } 'Low' { '#34d399' } default { '#94a3b8' } }
                [void]$sb.Append("<td><span style=`"color:$color;font-weight:700`">$(HtmlEncode $val)</span></td>")
            } else { [void]$sb.Append("<td>$(HtmlEncode $val)</td>") }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    if (@($Data).Count -gt $Limit) { [void]$sb.Append("<p class=`"empty-note`">Showing $Limit of $(@($Data).Count).</p>") }
    return $sb.ToString()
}

$CriticalPathTable = Build-Table -Data @($AllPaths | Where-Object { $_.Risk -eq 'Critical' } | Sort-Object Category,Principal) -Props @('Domain','Principal','PrincipalType','PathType','Target','Impact','Risk','RiskReason')
$AllPathTable = Build-Table -Data @($AllPaths | Sort-Object Risk,Category,Principal) -Props @('Domain','Category','Principal','PathType','Target','Chain','Risk') -Limit 500
$PrincipalTable = Build-Table -Data $TopPrincipals -Props @('Principal','Domain','Type','PrivGroups','Delegations','TotalAccess','IsServiceAccount','Risk','GroupList','DelegationList')
$GPOTable = Build-Table -Data $GPOPaths -Props @('Domain','GPO','Editor','LinkedTo','Risk')
$KerbDelegTable = Build-Table -Data $KerbDelegPaths -Props @('Domain','Account','Type','ObjectClass','DelegatesTo','Risk')
$DCSyncTable = Build-Table -Data $DCSyncPaths -Props @('Domain','Principal','Rights','FullDCSync','Risk')
$TrustTable = Build-Table -Data $TrustPaths -Props @('Domain','TrustedDomain','Direction','Type','SIDFiltering','SelectiveAuth','Risks','Risk')
$AdminSDTable = Build-Table -Data $AdminSDHolderAccts -Props @('Domain','Account','SPN','Groups')
$KerberoastTable = Build-Table -Data $KerberoastableAdmins -Props @('Domain','Account','SPN','Risk')
$NestedChainTable = Build-Table -Data $NestedChainPaths -Props @('Domain','User','TargetGroup','Chain','Depth','IsServiceAccount','IsDisabled','Risk')
$ASREPTable = Build-Table -Data $ASREPRoastable -Props @('Domain','Account','IsAdmin','Groups','Risk')
$SIDHistTable = Build-Table -Data $SIDHistoryAccts -Props @('Domain','Account','SIDHistoryCount','SIDHistory','IsAdmin','Risk')
$StaleAdminTable = Build-Table -Data $StaleAdmins -Props @('Domain','Account','DaysSinceLogon','DaysSincePwdChange','Groups','Risk')
$KRBTGTTable = Build-Table -Data $KRBTGTInfo -Props @('Domain','PasswordLastSet','AgeDays','Risk')
$MAQTable = Build-Table -Data $MAQInfo -Props @('Domain','Quota','Risk')

# Per-Domain Breakdown
$DomainBreakdownHTML = [System.Text.StringBuilder]::new()
foreach ($domainName in ($allDomains | Sort-Object)) {
    $dPaths = @($AllPaths | Where-Object { $_.Domain -eq $domainName })
    $dCrit = @($dPaths | Where-Object { $_.Risk -eq 'Critical' }).Count
    $dHigh = @($dPaths | Where-Object { $_.Risk -eq 'High' }).Count
    $dMed = @($dPaths | Where-Object { $_.Risk -eq 'Medium' }).Count
    $dGrp = @($dPaths | Where-Object { $_.Category -eq 'Group Membership' }).Count
    $dDel = @($dPaths | Where-Object { $_.Category -eq 'Delegation' }).Count
    $dGPO = @($dPaths | Where-Object { $_.Category -eq 'GPO' }).Count
    $dKerb = @($dPaths | Where-Object { $_.Category -eq 'Kerberos Delegation' }).Count
    $dSync = @($dPaths | Where-Object { $_.Category -eq 'DCSync' }).Count
    $dTrust = @($dPaths | Where-Object { $_.Category -eq 'Trust' }).Count
    $dKRoast = @($dPaths | Where-Object { $_.Category -eq 'Kerberoast' }).Count
    $dNested = @($dPaths | Where-Object { $_.Category -eq 'Nested Chain' }).Count
    $dASREP = @($dPaths | Where-Object { $_.Category -eq 'AS-REP Roast' }).Count
    $dSIDHist = @($dPaths | Where-Object { $_.Category -eq 'SID History' }).Count
    $dStale = @($dPaths | Where-Object { $_.Category -eq 'Stale Admin' }).Count
    $dKRBTGT = @($dPaths | Where-Object { $_.Category -eq 'KRBTGT' }).Count
    $dMAQ = @($dPaths | Where-Object { $_.Category -eq 'MAQ' }).Count
    $dAdminSD = @($AdminSDHolderAccts | Where-Object { $_.Domain -eq $domainName }).Count
    $borderColor = if ($dCrit -gt 0) { '#f87171' } elseif ($dHigh -gt 0) { '#fb923c' } else { '#334155' }

    [void]$DomainBreakdownHTML.Append(@"
<div style="background:#1e293b;border:1px solid #334155;border-left:4px solid $borderColor;border-radius:8px;padding:16px;margin-bottom:12px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
    <h3 style="font-size:.95rem;color:#e2e8f0;margin:0">$(HtmlEncode $domainName)</h3>
    <span style="font-size:.82rem;font-weight:700;color:$borderColor">$($dPaths.Count) paths</span>
  </div>
  <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">
    <span class="exec-kv" style="color:#f87171"><strong>Critical:</strong> $dCrit</span>
    <span class="exec-kv" style="color:#fb923c"><strong>High:</strong> $dHigh</span>
    <span class="exec-kv" style="color:#fbbf24"><strong>Medium:</strong> $dMed</span>
    <span class="exec-kv"><strong>Groups:</strong> $dGrp</span>
    <span class="exec-kv"><strong>Delegation:</strong> $dDel</span>
    $(if($dGPO -gt 0){"<span class='exec-kv'><strong>GPO:</strong> $dGPO</span>"})
    $(if($dKerb -gt 0){"<span class='exec-kv'><strong>Kerberos:</strong> $dKerb</span>"})
    $(if($dSync -gt 0){"<span class='exec-kv' style='color:#f87171'><strong>DCSync:</strong> $dSync</span>"})
    $(if($dTrust -gt 0){"<span class='exec-kv'><strong>Trust:</strong> $dTrust</span>"})
    $(if($dKRoast -gt 0){"<span class='exec-kv' style='color:#f87171'><strong>Kerberoast:</strong> $dKRoast</span>"})
    $(if($dNested -gt 0){"<span class='exec-kv' style='color:#f472b6'><strong>Nested Chains:</strong> $dNested</span>"})
    $(if($dASREP -gt 0){"<span class='exec-kv' style='color:#f87171'><strong>AS-REP:</strong> $dASREP</span>"})
    $(if($dSIDHist -gt 0){"<span class='exec-kv' style='color:#fbbf24'><strong>SID Hist:</strong> $dSIDHist</span>"})
    $(if($dStale -gt 0){"<span class='exec-kv' style='color:#fb923c'><strong>Stale Admins:</strong> $dStale</span>"})
    $(if($dKRBTGT -gt 0){"<span class='exec-kv' style='color:#f87171'><strong>KRBTGT:</strong> $dKRBTGT</span>"})
    $(if($dMAQ -gt 0){"<span class='exec-kv'><strong>MAQ:</strong> $dMAQ</span>"})
    $(if($dAdminSD -gt 0){"<span class='exec-kv'><strong>AdminSDHolder:</strong> $dAdminSD</span>"})
  </div>
"@)

    # Critical paths table for this domain
    $domCritPaths = @($dPaths | Where-Object { $_.Risk -eq 'Critical' })
    if ($domCritPaths.Count -gt 0) {
        $domCritTable = Build-Table -Data $domCritPaths -Props @('Principal','PathType','Target','Impact','Risk') -Limit 20
        [void]$DomainBreakdownHTML.Append("<div style='font-size:.7rem;color:#f87171;text-transform:uppercase;margin-bottom:4px;font-weight:700'>Critical Paths</div>$domCritTable")
    }
    # High-risk paths for this domain (top 10)
    $domHighPaths = @($dPaths | Where-Object { $_.Risk -eq 'High' })
    if ($domHighPaths.Count -gt 0 -and $domCritPaths.Count -lt 10) {
        $domHighTable = Build-Table -Data ($domHighPaths | Select-Object -First 10) -Props @('Principal','PathType','Target','Risk') -Limit 10
        [void]$DomainBreakdownHTML.Append("<div style='font-size:.7rem;color:#fb923c;text-transform:uppercase;margin-top:8px;margin-bottom:4px;font-weight:700'>High-Risk Paths (Top 10)</div>$domHighTable")
    }
    [void]$DomainBreakdownHTML.Append("</div>")
}

# Attack scenario cards HTML
$ScenarioHTML = [System.Text.StringBuilder]::new()
foreach ($s in ($AttackScenarios | Sort-Object @{E={switch($_.Severity){'Critical'{0}'High'{1}'Medium'{2}default{3}}}})) {
    $sevColor = switch ($s.Severity) { 'Critical' { '#f87171' } 'High' { '#fb923c' } 'Medium' { '#fbbf24' } default { '#94a3b8' } }
    $steps = ($s.AttackSteps -split '\|' | ForEach-Object { "<li style=`"margin:3px 0;color:#94a3b8;font-size:.8rem`">$_</li>" }) -join ''
    $affected = ($s.Affected -split '\|' | ForEach-Object { "<div style=`"font-size:.76rem;color:#e2e8f0;padding:2px 0`">$_</div>" }) -join ''
    [void]$ScenarioHTML.Append(@"
<div style="background:#1e293b;border:1px solid #334155;border-left:4px solid $sevColor;border-radius:8px;padding:16px;margin-bottom:12px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
    <h3 style="font-size:.92rem;color:#e2e8f0;margin:0">$(HtmlEncode $s.Scenario)</h3>
    <span style="color:$sevColor;font-weight:700;font-size:.82rem">$($s.Severity) ($($s.Count))</span>
  </div>
  <p style="color:#94a3b8;font-size:.82rem;margin-bottom:8px">$(HtmlEncode $s.Description)</p>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
    <div><div style="font-size:.7rem;color:#60a5fa;text-transform:uppercase;margin-bottom:4px">Attack Steps</div><ol style="padding-left:16px;margin:0">$steps</ol></div>
    <div><div style="font-size:.7rem;color:#60a5fa;text-transform:uppercase;margin-bottom:4px">Affected</div>$affected</div>
  </div>
  <div style="margin-top:8px;padding:8px;background:#273548;border-radius:4px"><span style="font-size:.7rem;color:#34d399;text-transform:uppercase">Remediation: </span><span style="font-size:.78rem;color:#e2e8f0">$(HtmlEncode $s.Remediation)</span></div>
</div>
"@)
}

# SVG Attack Path Diagram -- deduplicate by picking diverse paths across categories
$critAll = @($AllPaths | Where-Object { $_.Risk -eq 'Critical' } | Sort-Object Category,Principal)
$critSeen = @{}; $critPaths = @()
foreach ($cp in $critAll) {
    $key = "$($cp.Principal)->$($cp.Target)"
    if ($critSeen.ContainsKey($key)) { continue }
    $critSeen[$key] = $true
    $critPaths += $cp
    if ($critPaths.Count -ge 15) { break }
}
$svgWidth = 720
$svgHeight = [math]::Max(400, 60 + ($critPaths.Count * 56))
$svgNodes = [System.Text.StringBuilder]::new()
$yPos = 50
foreach ($cp in $critPaths) {
    $principalColor = if ($cp.IsServiceAccount) { '#f87171' } elseif ($cp.PrincipalType -eq 'group') { '#a78bfa' } elseif ($cp.Category -eq 'DCSync') { '#22d3ee' } elseif ($cp.Category -eq 'Trust') { '#fbbf24' } else { '#60a5fa' }
    $targetColor = '#f87171'
    $lineColor = '#fb923c'
    $domShort = ($cp.Domain -replace '\.lab$','')
    $pName = if ($cp.Principal.Length -gt 18) { $cp.Principal.Substring(0,15) + '...' } else { $cp.Principal }
    $tName = if ($cp.Target.Length -gt 22) { $cp.Target.Substring(0,19) + '...' } else { $cp.Target }
    $pType = $cp.PathType
    if ($pType.Length -gt 18) { $pType = $pType.Substring(0,15) + '...' }
    [void]$svgNodes.Append(@"
  <rect x="20" y="$($yPos-16)" width="190" height="32" rx="6" fill="$principalColor" fill-opacity="0.15" stroke="$principalColor" stroke-width="1.5"/>
  <text x="115" y="$($yPos-1)" text-anchor="middle" fill="$principalColor" font-size="11" font-weight="600">$([System.Web.HttpUtility]::HtmlEncode($pName))</text>
  <text x="115" y="$($yPos+10)" text-anchor="middle" fill="#64748b" font-size="8">$([System.Web.HttpUtility]::HtmlEncode($domShort))</text>
  <line x1="210" y1="$yPos" x2="390" y2="$yPos" stroke="$lineColor" stroke-width="2" stroke-dasharray="6,3"/>
  <polygon points="385,$($yPos-5) 395,$yPos 385,$($yPos+5)" fill="$lineColor"/>
  <text x="300" y="$($yPos-8)" text-anchor="middle" fill="#94a3b8" font-size="9">$([System.Web.HttpUtility]::HtmlEncode($pType))</text>
  <rect x="400" y="$($yPos-16)" width="240" height="32" rx="6" fill="$targetColor" fill-opacity="0.15" stroke="$targetColor" stroke-width="1.5"/>
  <text x="520" y="$($yPos+2)" text-anchor="middle" fill="$targetColor" font-size="11" font-weight="600">$([System.Web.HttpUtility]::HtmlEncode($tName))</text>
"@)
    $yPos += 56
}

# Build multi-hop chain diagram for nested paths (depth >= 2)
$chainDiagPaths = @($NestedChainPaths | Sort-Object Depth -Descending | Select-Object -First 10)
$chainSvgHeight = [math]::Max(200, 50 + ($chainDiagPaths.Count * 58))
$chainSvg = [System.Text.StringBuilder]::new()
$chainY = 45
foreach ($nc in $chainDiagPaths) {
    $steps = $nc.Chain -split ' -> '
    $stepCount = $steps.Count
    if ($stepCount -lt 2) { continue }
    # Calculate node widths to fit in 700px
    $nodeW = [math]::Min(130, [math]::Floor(640 / $stepCount))
    $gapW = if ($stepCount -gt 1) { [math]::Floor((680 - ($nodeW * $stepCount)) / ($stepCount - 1)) } else { 0 }
    $xPos = 20
    for ($i = 0; $i -lt $stepCount; $i++) {
        $stepName = $steps[$i].Trim()
        if ($stepName.Length -gt ($nodeW / 7)) { $stepName = $stepName.Substring(0, [math]::Max(3, [math]::Floor($nodeW / 7) - 2)) + '..' }
        # Color: first = blue (user), last = red (target group), middle = purple (groups)
        $nodeColor = if ($i -eq 0) { '#60a5fa' } elseif ($i -eq ($stepCount - 1)) { '#f87171' } else { '#a78bfa' }
        [void]$chainSvg.Append("<rect x=`"$xPos`" y=`"$($chainY-12)`" width=`"$nodeW`" height=`"24`" rx=`"5`" fill=`"$nodeColor`" fill-opacity=`"0.15`" stroke=`"$nodeColor`" stroke-width=`"1.2`"/>")
        [void]$chainSvg.Append("<text x=`"$($xPos + $nodeW/2)`" y=`"$($chainY+3)`" text-anchor=`"middle`" fill=`"$nodeColor`" font-size=`"9`" font-weight=`"600`">$([System.Web.HttpUtility]::HtmlEncode($stepName))</text>")
        # Arrow to next node
        if ($i -lt ($stepCount - 1)) {
            $arrowX1 = $xPos + $nodeW
            $arrowX2 = $xPos + $nodeW + $gapW
            [void]$chainSvg.Append("<line x1=`"$arrowX1`" y1=`"$chainY`" x2=`"$($arrowX2-4)`" y2=`"$chainY`" stroke=`"#fb923c`" stroke-width=`"1.5`" stroke-dasharray=`"4,2`"/>")
            [void]$chainSvg.Append("<polygon points=`"$($arrowX2-7),$($chainY-3) $($arrowX2),$chainY $($arrowX2-7),$($chainY+3)`" fill=`"#fb923c`"/>")
        }
        $xPos += $nodeW + $gapW
    }
    # Domain label at the end
    $domShort = ($nc.Domain -replace '\.lab$','')
    [void]$chainSvg.Append("<text x=`"710`" y=`"$($chainY+3)`" text-anchor=`"end`" fill=`"#64748b`" font-size=`"8`">$([System.Web.HttpUtility]::HtmlEncode($domShort))</text>")
    $chainY += 58
}

# Chart JSON
$RiskChartJSON = '{"Critical":' + $CriticalPaths + ',"High":' + $HighPaths + ',"Medium":' + $MediumPaths + '}'
$CategoryJSON = '{"Group":' + $GroupPaths + ',"Delegation":' + $DelegPaths + ',"Nested":' + $NestedChainCount + ',"GPO":' + $GPOPathCount + ',"Kerb Deleg":' + $KerbPathCount + ',"DCSync":' + $DCSyncCount + ',"Trust":' + $TrustPathCount + ',"Kerberoast":' + $KerberoastCount + ',"AS-REP":' + $ASREPCount + ',"SID Hist":' + $SIDHistCount + ',"Stale Admin":' + $StaleAdminCount + ',"KRBTGT":' + $KRBTGTCount + ',"MAQ":' + $MAQCount + '}'
$ScenarioRiskJSON = '{"Critical":' + @($AttackScenarios | Where-Object {$_.Severity -eq 'Critical'}).Count + ',"High":' + @($AttackScenarios | Where-Object {$_.Severity -eq 'High'}).Count + ',"Medium":' + @($AttackScenarios | Where-Object {$_.Severity -eq 'Medium'}).Count + '}'
# Top principals chart
$TopPrincJSON = '{' + (($TopPrincipals | Select-Object -First 10 | ForEach-Object { '"' + ($_.Principal -replace '"','') + '":' + $_.TotalAccess }) -join ',') + '}'
if ($TopPrincJSON -eq '{}') { $TopPrincJSON = '{"None":0}' }

# ==============================================================================
# HTML
# ==============================================================================
$HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="author" content="Santhosh Sivarajan, Microsoft MVP"/>
<title>AttackPathCanvas -- $ForestName</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0f172a;--surface:#1e293b;--surface2:#273548;--border:#334155;--text:#e2e8f0;--text-dim:#94a3b8;--accent:#60a5fa;--accent2:#22d3ee;--green:#34d399;--red:#f87171;--amber:#fbbf24;--purple:#a78bfa;--pink:#f472b6;--orange:#fb923c;--radius:8px;--shadow:0 1px 3px rgba(0,0,0,.3);--font-body:'Segoe UI',system-ui,sans-serif}
html{scroll-behavior:smooth;font-size:15px}body{font-family:var(--font-body);background:var(--bg);color:var(--text);line-height:1.65;min-height:100vh}a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrapper{display:flex;min-height:100vh}.sidebar{position:fixed;top:0;left:0;width:260px;height:100vh;background:var(--surface);border-right:1px solid var(--border);overflow-y:auto;padding:20px 0;z-index:100;box-shadow:2px 0 12px rgba(0,0,0,.3)}.sidebar::-webkit-scrollbar{width:4px}.sidebar::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}.sidebar .logo{padding:0 18px 14px;border-bottom:1px solid var(--border);margin-bottom:8px}.sidebar .logo h2{font-size:1.05rem;color:var(--accent);font-weight:700}.sidebar .logo p{font-size:.68rem;color:var(--text-dim);margin-top:2px}.sidebar nav a{display:block;padding:5px 18px 5px 22px;font-size:.78rem;color:var(--text-dim);border-left:3px solid transparent;transition:all .15s}.sidebar nav a:hover,.sidebar nav a.active{color:var(--accent);background:rgba(96,165,250,.08);border-left-color:var(--accent);text-decoration:none}.sidebar nav .nav-group{font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:var(--accent2);padding:10px 18px 2px;font-weight:700}
.main{margin-left:260px;flex:1;padding:24px 32px 50px;max-width:1200px}.section{margin-bottom:36px}.section-title{font-size:1.25rem;font-weight:700;color:var(--text);margin-bottom:4px;padding-bottom:8px;border-bottom:2px solid var(--border);display:flex;align-items:center;gap:8px}.section-title .icon{width:24px;height:24px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:.8rem;flex-shrink:0}.sub-header{font-size:.92rem;color:var(--text);margin:16px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--border)}.section-desc{color:var(--text-dim);font-size:.84rem;margin-bottom:14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:16px}.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;box-shadow:var(--shadow)}.card:hover{border-color:var(--accent)}.card .card-val{font-size:1.5rem;font-weight:800;line-height:1.1}.card .card-label{font-size:.68rem;color:var(--text-dim);margin-top:2px;text-transform:uppercase;letter-spacing:.05em}
.table-wrap{overflow-x:auto;margin-bottom:8px;border-radius:var(--radius);border:1px solid var(--border);box-shadow:var(--shadow)}table{width:100%;border-collapse:collapse;font-size:.75rem}thead{background:rgba(96,165,250,.1)}th{text-align:left;padding:8px 10px;font-weight:600;color:var(--accent);white-space:nowrap;border-bottom:2px solid var(--border)}td{padding:6px 10px;border-bottom:1px solid var(--border);color:var(--text-dim);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}tbody tr:hover{background:rgba(96,165,250,.06)}tbody tr:nth-child(even){background:var(--surface2)}.empty-note{color:var(--text-dim);font-style:italic;padding:8px 0}
.score-card{background:linear-gradient(135deg,#1e293b 0%,#3b1e1e 100%);border:1px solid #334155;border-radius:var(--radius);padding:28px;margin-bottom:28px;text-align:center;box-shadow:var(--shadow)}
.exec-kv{display:inline-block;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:2px 8px;margin:2px;font-size:.78rem;color:var(--text)}.exec-kv strong{color:var(--accent2)}
.footer{margin-top:36px;padding:18px 0;border-top:1px solid var(--border);text-align:center;color:var(--text-dim);font-size:.74rem}.footer a{color:var(--accent)}
@media print{.sidebar{display:none}.main{margin-left:0}body{background:#fff;color:#222}.card,.score-card{background:#f9f9f9;border-color:#ccc;color:#222}th{color:#333;background:#eee}td{color:#444}}
@media(max-width:900px){.sidebar{display:none}.main{margin-left:0;padding:14px}}
</style>
</head>
<body>
<div class="wrapper">
<aside class="sidebar">
  <div class="logo"><h2>AttackPathCanvas</h2><p>Developed by Santhosh Sivarajan</p><p style="margin-top:6px">Forest: <strong style="color:#e2e8f0">$ForestName</strong></p></div>
  <nav>
    <div class="nav-group">Overview</div>
    <a href="#summary">Risk Summary</a>
    <a href="#per-domain">Per-Domain Breakdown</a>
    <a href="#diagram">Attack Path Diagram</a>
    <div class="nav-group">Analysis</div>
    <a href="#scenarios">Attack Scenarios</a>
    <a href="#critical">Critical Paths</a>
    <a href="#principals">Principal Risk Profiles</a>
    <div class="nav-group">Attack Surfaces</div>
    <a href="#gpo-paths">GPO Attack Paths</a>
    <a href="#nested-chains">Nested Group Chains</a>
    <a href="#kerb-deleg">Kerberos Delegation</a>
    <a href="#dcsync">DCSync Accounts</a>
    <a href="#trusts">Trust Weaknesses</a>
    <a href="#adminsdholder">AdminSDHolder</a>
    <a href="#asrep">AS-REP Roastable</a>
    <a href="#sidhistory">SID History</a>
    <a href="#stale-admins">Stale Admins</a>
    <a href="#krbtgt">KRBTGT Password</a>
    <a href="#maq">Machine Account Quota</a>
    <div class="nav-group">Details</div>
    <a href="#all-paths">All Attack Paths</a>
    <a href="#charts">Charts</a>
  </nav>
</aside>
<main class="main">

<div id="summary" class="section">
  <div class="score-card">
    <div style="font-size:3rem;font-weight:900;color:$(if($CriticalPaths -gt 0){'#f87171'}elseif($HighPaths -gt 0){'#fb923c'}else{'#34d399'})">$TotalPaths</div>
    <div style="font-size:.9rem;color:#94a3b8;margin-top:4px">Attack Paths Discovered</div>
    <div style="margin-top:12px">
      <span class="exec-kv"><strong>Forest:</strong> $ForestName</span>
      <span class="exec-kv"><strong>Domains:</strong> $($allDomains.Count)</span>
      <span class="exec-kv" style="color:#f87171"><strong>Critical:</strong> $CriticalPaths</span>
      <span class="exec-kv" style="color:#fb923c"><strong>High:</strong> $HighPaths</span>
      <span class="exec-kv" style="color:#fbbf24"><strong>Medium:</strong> $MediumPaths</span>
      <span class="exec-kv"><strong>Attack Scenarios:</strong> $($AttackScenarios.Count)</span>
      <span class="exec-kv"><strong>Group Paths:</strong> $GroupPaths</span>
      <span class="exec-kv"><strong>Delegation Paths:</strong> $DelegPaths</span>
      <span class="exec-kv"><strong>GPO Paths:</strong> $GPOPathCount</span>
      <span class="exec-kv"><strong>Kerberos Deleg:</strong> $KerbPathCount</span>
      <span class="exec-kv"><strong>DCSync:</strong> $DCSyncCount</span>
      <span class="exec-kv"><strong>Trust Risks:</strong> $TrustPathCount</span>
      <span class="exec-kv"><strong>Kerberoastable:</strong> $KerberoastCount</span>
      <span class="exec-kv" style="color:#f472b6"><strong>Nested Chains:</strong> $NestedChainCount</span>
      <span class="exec-kv"><strong>AdminSDHolder:</strong> $($AdminSDHolderAccts.Count)</span>
      <span class="exec-kv"><strong>AS-REP Roast:</strong> $ASREPCount</span>
      <span class="exec-kv"><strong>SID History:</strong> $SIDHistCount</span>
      <span class="exec-kv"><strong>Stale Admins:</strong> $StaleAdminCount</span>
      <span class="exec-kv"><strong>Principals at Risk:</strong> $($PrincipalProfiles.Count)</span>
    </div>
  </div>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:#f87171">$CriticalPaths</div><div class="card-label">Critical Paths</div></div>
    <div class="card"><div class="card-val" style="color:#fb923c">$HighPaths</div><div class="card-label">High Paths</div></div>
    <div class="card"><div class="card-val" style="color:#fbbf24">$MediumPaths</div><div class="card-label">Medium Paths</div></div>
    <div class="card"><div class="card-val" style="color:#f87171">$($AttackScenarios.Count)</div><div class="card-label">Attack Scenarios</div></div>
    <div class="card"><div class="card-val" style="color:#60a5fa">$GroupPaths</div><div class="card-label">Group Membership</div></div>
    <div class="card"><div class="card-val" style="color:#a78bfa">$DelegPaths</div><div class="card-label">Delegation Paths</div></div>
    <div class="card"><div class="card-val" style="color:#22d3ee">$GPOPathCount</div><div class="card-label">GPO Paths</div></div>
    <div class="card"><div class="card-val" style="color:#f472b6">$KerbPathCount</div><div class="card-label">Kerberos Deleg</div></div>
  </div>
</div>

<div id="per-domain" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(34,211,238,.15);color:var(--accent2)">&#127760;</span> Per-Domain Breakdown</h2>
  <p class="section-desc">Attack path findings organized by domain. Each domain shows its critical and high-risk paths so domain administrators can focus on their own scope.</p>
  $($DomainBreakdownHTML.ToString())
</div>

<div id="diagram" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#9889;</span> Attack Path Diagram -- Critical Paths</h2>
  <p class="section-desc">Visual representation of the most critical attack paths. Blue = user accounts, Purple = groups, Red = service accounts. Arrows show the escalation path to the target.</p>
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;overflow-x:auto">
    <svg width="$svgWidth" height="$svgHeight" viewBox="0 0 $svgWidth $svgHeight" xmlns="http://www.w3.org/2000/svg">
      <text x="115" y="24" text-anchor="middle" fill="#60a5fa" font-size="12" font-weight="700">Principal</text>
      <text x="300" y="24" text-anchor="middle" fill="#94a3b8" font-size="10">Path Type</text>
      <text x="520" y="24" text-anchor="middle" fill="#f87171" font-size="12" font-weight="700">Target</text>
      <line x1="20" y1="32" x2="640" y2="32" stroke="#334155" stroke-width="1"/>
      $($svgNodes.ToString())
    </svg>
  </div>
  $(if($chainDiagPaths.Count -gt 0) {
  @"
  <h3 class="sub-header">Nested Group Chains -- Multi-Hop Paths (Top $($chainDiagPaths.Count))</h3>
  <p class="section-desc" style="margin-top:4px">Full chain visualization showing how users reach privileged groups through nested group membership. Blue = user, Purple = intermediate groups, Red = target admin group. Sorted by depth (deepest first).</p>
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;overflow-x:auto">
    <svg width="720" height="$chainSvgHeight" viewBox="0 0 720 $chainSvgHeight" xmlns="http://www.w3.org/2000/svg">
      <text x="20" y="20" fill="#60a5fa" font-size="10" font-weight="700">User</text>
      <text x="360" y="20" text-anchor="middle" fill="#a78bfa" font-size="10" font-weight="700">Group Chain</text>
      <text x="640" y="20" text-anchor="end" fill="#f87171" font-size="10" font-weight="700">Target</text>
      <text x="710" y="20" text-anchor="end" fill="#64748b" font-size="9">Domain</text>
      <line x1="20" y1="28" x2="710" y2="28" stroke="#334155" stroke-width="1"/>
      $($chainSvg.ToString())
    </svg>
  </div>
"@
  })
</div>

<div id="scenarios" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#128163;</span> Attack Scenarios ($($AttackScenarios.Count))</h2>
  <p class="section-desc">Identified attack scenarios with step-by-step exploitation paths and remediation guidance.</p>
  $($ScenarioHTML.ToString())
  $(if($AttackScenarios.Count -eq 0){'<p class="empty-note">No attack scenarios identified -- excellent security posture!</p>'}else{''})
</div>

<div id="critical" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#9888;</span> Critical Attack Paths ($CriticalPaths)</h2>
  <p class="section-desc">All paths classified as Critical risk. These represent the most dangerous escalation opportunities.</p>
  $CriticalPathTable
</div>

<div id="principals" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128100;</span> Principal Risk Profiles (Top 25)</h2>
  <p class="section-desc">Principals ranked by total access (privileged group memberships + dangerous delegations). Higher count = larger blast radius if compromised.</p>
  $PrincipalTable
</div>

<div id="gpo-paths" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(34,211,238,.15);color:var(--accent2)">&#128196;</span> GPO Attack Paths ($GPOPathCount)</h2>
  <p class="section-desc">Non-admin principals who can edit Group Policy Objects. GPO modification enables arbitrary code execution on every computer where the GPO applies. GPOs linked to Domain Controllers or Tier 0 OUs are critical risks.</p>
  $GPOTable
</div>

<div id="nested-chains" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(244,114,182,.15);color:var(--pink)">&#128279;</span> Nested Group Chains ($NestedChainCount)</h2>
  <p class="section-desc">Users who are effectively admins through deeply nested group membership. These hidden admin paths are invisible in standard tools like ADUC which only show direct members. A user nested 3+ levels deep is a significant audit blind spot.</p>
  $NestedChainTable
</div>

<div id="kerb-deleg" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(244,114,182,.15);color:var(--pink)">&#128274;</span> Kerberos Delegation ($KerbPathCount)</h2>
  <p class="section-desc">Accounts and computers with Kerberos delegation configured. Unconstrained delegation caches every authenticating user's TGT. Constrained delegation with protocol transition enables impersonation. RBCD allows controlled impersonation to specific targets.</p>
  $KerbDelegTable
</div>

<div id="dcsync" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#128275;</span> DCSync-Capable Accounts ($DCSyncCount)</h2>
  <p class="section-desc">Non-default accounts with Replicating Directory Changes rights on the domain root. These accounts can perform DCSync to extract all password hashes including KRBTGT (Golden Ticket).</p>
  $DCSyncTable
</div>

<div id="trusts" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(251,191,36,.15);color:var(--amber)">&#127760;</span> Trust Weaknesses ($TrustPathCount)</h2>
  <p class="section-desc">Domain and forest trusts with security weaknesses. Disabled SID filtering enables cross-trust SID injection. Missing selective authentication allows unrestricted access. TGT delegation enables unconstrained delegation abuse across trust boundaries.</p>
  $TrustTable
</div>

<div id="adminsdholder" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(167,139,250,.15);color:var(--purple)">&#128737;</span> AdminSDHolder Protected Accounts ($($AdminSDHolderAccts.Count))</h2>
  <p class="section-desc">Accounts with AdminCount=1 (protected by AdminSDHolder ACL reset every 60 minutes). Accounts with SPNs are Kerberoastable -- any domain user can request and crack their service ticket offline.</p>
  <h3 class="sub-header">All AdminSDHolder Accounts</h3>
  $AdminSDTable
  <h3 class="sub-header">Kerberoastable Admin Accounts ($($KerberoastableAdmins.Count))</h3>
  $KerberoastTable
</div>

<div id="asrep" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#128275;</span> AS-REP Roastable Accounts ($($ASREPRoastable.Count))</h2>
  <p class="section-desc">Accounts with Kerberos pre-authentication disabled (DONT_REQ_PREAUTH). ANY domain user can request an AS-REP and crack the password offline without generating failed logon events. Admin accounts with this setting are critical risk.</p>
  $ASREPTable
</div>

<div id="sidhistory" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(251,191,36,.15);color:var(--amber)">&#128279;</span> SID History ($($SIDHistoryAccts.Count))</h2>
  <p class="section-desc">Accounts carrying SID History entries from domain migrations. Historical SIDs are automatically included in Kerberos tickets, granting access as the original account. If any SID maps to a privileged account, this user effectively has admin access.</p>
  $SIDHistTable
</div>

<div id="stale-admins" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(251,146,60,.15);color:var(--orange)">&#128164;</span> Stale Admin Accounts ($($StaleAdmins.Count))</h2>
  <p class="section-desc">Admin accounts (AdminCount=1) that have not logged in for 90+ days but remain enabled with admin privileges. Forgotten accounts are prime targets for attackers -- they are rarely monitored and may have weak or unchanged passwords.</p>
  $StaleAdminTable
</div>

<div id="krbtgt" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#128272;</span> KRBTGT Password Age</h2>
  <p class="section-desc">KRBTGT is the service account that encrypts all Kerberos tickets. If its password has not been rotated, any attacker who ever obtained the hash can create Golden Tickets (unlimited domain access). Microsoft recommends rotating every 180 days.</p>
  $KRBTGTTable
</div>

<div id="maq" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(34,211,238,.15);color:var(--accent2)">&#128187;</span> Machine Account Quota</h2>
  <p class="section-desc">MachineAccountQuota controls how many computer accounts any domain user can create. The default is 10. If > 0, any user can create machine accounts and use them for RBCD attacks. Should be set to 0 in all production environments.</p>
  $MAQTable
</div>

<div id="all-paths" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(167,139,250,.15);color:var(--purple)">&#128220;</span> All Attack Paths ($TotalPaths)</h2>
  $AllPathTable
</div>

<div id="charts" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128202;</span> Charts</h2>
  <div id="chartsContainer" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px"></div>
</div>

<div class="footer">
  AttackPathCanvas v1.1 -- Identity Attack Path Report -- $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
  Developed by <a href="https://github.com/SanthoshSivarajan">Santhosh Sivarajan</a>, Microsoft MVP --
  <a href="https://github.com/SanthoshSivarajan/AttackPathCanvas">github.com/SanthoshSivarajan/AttackPathCanvas</a>
</div>
</main>
</div>
<script>
var COLORS=['#60a5fa','#34d399','#f87171','#fbbf24','#a78bfa','#f472b6','#22d3ee','#fb923c','#a3e635','#e879f9'];
function buildBarChart(t,d,c){var b=document.createElement('div');b.style.cssText='background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;box-shadow:var(--shadow)';var h=document.createElement('h3');h.style.cssText='font-size:.86rem;margin-bottom:10px;color:#e2e8f0';h.textContent=t;b.appendChild(h);var tot=Object.values(d).reduce(function(a,b){return a+b},0);if(!tot){b.innerHTML+='<p style="color:#94a3b8">No data.</p>';c.appendChild(b);return}var g=document.createElement('div');g.style.cssText='display:flex;flex-direction:column;gap:6px';var e=Object.entries(d),ci=0;for(var i=0;i<e.length;i++){var p=((e[i][1]/tot)*100).toFixed(1);var r=document.createElement('div');r.style.cssText='display:flex;align-items:center;gap:8px';r.innerHTML='<span style="width:130px;font-size:.72rem;color:#94a3b8;text-align:right;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+e[i][0]+'</span><div style="flex:1;height:20px;background:#273548;border-radius:4px;overflow:hidden;border:1px solid #334155"><div style="height:100%;border-radius:3px;width:'+p+'%;background:'+COLORS[ci%COLORS.length]+';display:flex;align-items:center;padding:0 6px;font-size:.66rem;font-weight:600;color:#fff;white-space:nowrap">'+p+'%</div></div><span style="width:36px;font-size:.74rem;color:#94a3b8;text-align:right">'+e[i][1]+'</span>';g.appendChild(r);ci++}b.appendChild(g);c.appendChild(b)}
function buildDonut(t,d,c){var b=document.createElement('div');b.style.cssText='background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;box-shadow:var(--shadow)';var h=document.createElement('h3');h.style.cssText='font-size:.86rem;margin-bottom:10px;color:#e2e8f0';h.textContent=t;b.appendChild(h);var tot=Object.values(d).reduce(function(a,b){return a+b},0);if(!tot){b.innerHTML+='<p style="color:#94a3b8">No data.</p>';c.appendChild(b);return}var dc=document.createElement('div');dc.style.cssText='display:flex;align-items:center;gap:18px;flex-wrap:wrap';var sz=130,cx=65,cy=65,r=48,cf=2*Math.PI*r;var s='<svg width="'+sz+'" height="'+sz+'" viewBox="0 0 '+sz+' '+sz+'">';var off=0,ci=0,e=Object.entries(d);for(var i=0;i<e.length;i++){var pc=e[i][1]/tot,da=pc*cf,ga=cf-da;s+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+COLORS[ci%COLORS.length]+'" stroke-width="14" stroke-dasharray="'+da.toFixed(2)+' '+ga.toFixed(2)+'" stroke-dashoffset="'+(-off).toFixed(2)+'" transform="rotate(-90 '+cx+' '+cy+')" />';off+=da;ci++}s+='<text x="'+cx+'" y="'+cy+'" text-anchor="middle" dominant-baseline="central" fill="#e2e8f0" font-size="18" font-weight="700">'+tot+'</text></svg>';dc.innerHTML=s;var lg=document.createElement('div');lg.style.cssText='display:flex;flex-direction:column;gap:3px';ci=0;for(var i=0;i<e.length;i++){var pc=((e[i][1]/tot)*100).toFixed(1);var it=document.createElement('div');it.style.cssText='display:flex;align-items:center;gap:6px;font-size:.74rem;color:#94a3b8';it.innerHTML='<span style="width:10px;height:10px;border-radius:2px;background:'+COLORS[ci%COLORS.length]+';flex-shrink:0"></span>'+e[i][0]+': '+e[i][1]+' ('+pc+'%)';lg.appendChild(it);ci++}dc.appendChild(lg);b.appendChild(dc);c.appendChild(b)}
(function(){var c=document.getElementById('chartsContainer');if(!c)return;
buildDonut('Path Risk Distribution',$RiskChartJSON,c);
buildDonut('Path Categories',$CategoryJSON,c);
buildDonut('Scenario Severity',$ScenarioRiskJSON,c);
buildBarChart('Principal Risk (Top 10)',$TopPrincJSON,c);
})();
(function(){var lk=document.querySelectorAll('.sidebar nav a');var sc=[];for(var i=0;i<lk.length;i++){var id=lk[i].getAttribute('href');if(id&&id.charAt(0)==='#'){var el=document.querySelector(id);if(el)sc.push({el:el,link:lk[i]})}}window.addEventListener('scroll',function(){var cur=sc[0];for(var i=0;i<sc.length;i++){if(sc[i].el.getBoundingClientRect().top<=120)cur=sc[i]}for(var i=0;i<lk.length;i++)lk[i].classList.remove('active');if(cur)cur.link.classList.add('active')})})();
</script>
</body>
</html>
"@

$HTML | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
$FileSize = [math]::Round((Get-Item $OutputFile).Length / 1KB, 1)

Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host "  |   AttackPathCanvas -- Report Generation Complete           |" -ForegroundColor Green
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  ATTACK PATH SUMMARY" -ForegroundColor White
Write-Host "  --------------------" -ForegroundColor Gray
Write-Host "    Total Paths       : $TotalPaths" -ForegroundColor White
Write-Host "    Critical          : $CriticalPaths" -ForegroundColor $(if($CriticalPaths -gt 0){'Red'}else{'Green'})
Write-Host "    High              : $HighPaths" -ForegroundColor $(if($HighPaths -gt 0){'Yellow'}else{'Green'})
Write-Host "    Medium            : $MediumPaths" -ForegroundColor White
Write-Host "    Attack Scenarios  : $($AttackScenarios.Count)" -ForegroundColor $(if($AttackScenarios.Count -gt 0){'Red'}else{'Green'})
Write-Host "    Group Membership  : $GroupPaths" -ForegroundColor White
Write-Host "    Delegation Paths  : $DelegPaths" -ForegroundColor White
Write-Host "    GPO Paths         : $GPOPathCount" -ForegroundColor White
Write-Host "    Kerberos Deleg    : $KerbPathCount" -ForegroundColor White
Write-Host "    DCSync Accounts   : $DCSyncCount" -ForegroundColor $(if($DCSyncCount -gt 0){'Red'}else{'Green'})
Write-Host "    Trust Weaknesses  : $TrustPathCount" -ForegroundColor White
Write-Host "    Kerberoastable    : $KerberoastCount" -ForegroundColor $(if($KerberoastCount -gt 0){'Red'}else{'Green'})
Write-Host "    Nested Chains     : $NestedChainCount" -ForegroundColor $(if($NestedChainCount -gt 0){'Red'}else{'Green'})
Write-Host "    AdminSDHolder     : $($AdminSDHolderAccts.Count)" -ForegroundColor White
Write-Host "    AS-REP Roastable  : $ASREPCount" -ForegroundColor $(if($ASREPCount -gt 0){'Red'}else{'Green'})
Write-Host "    SID History       : $SIDHistCount" -ForegroundColor $(if($SIDHistCount -gt 0){'Yellow'}else{'Green'})
Write-Host "    Stale Admins      : $StaleAdminCount" -ForegroundColor $(if($StaleAdminCount -gt 0){'Yellow'}else{'Green'})
Write-Host "    KRBTGT Stale      : $KRBTGTCount" -ForegroundColor $(if($KRBTGTCount -gt 0){'Red'}else{'Green'})
Write-Host "    MAQ Risky         : $MAQCount" -ForegroundColor $(if($MAQCount -gt 0){'Yellow'}else{'Green'})
Write-Host "    Principals at Risk: $($PrincipalProfiles.Count)" -ForegroundColor White
Write-Host ""
Write-Host "    Report File : $OutputFile" -ForegroundColor White
Write-Host "    File Size   : $FileSize KB" -ForegroundColor White
Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host "  |  This report was generated using AttackPathCanvas v1.1     |" -ForegroundColor Cyan
Write-Host "  |  Developed by Santhosh Sivarajan, Microsoft MVP            |" -ForegroundColor Cyan
Write-Host "  |  https://github.com/SanthoshSivarajan/AttackPathCanvas     |" -ForegroundColor Cyan
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host ""

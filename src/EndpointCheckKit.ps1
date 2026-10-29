<#
.SYNOPSIS
    Endpoint Security Check Kit - Windows 10/11 사용자 PC 보안 설정 읽기 전용 점검 스크립트

.DESCRIPTION
    사용자 PC의 보안 설정을 읽기만 하고, 결과를 한국어 HTML 보고서와 CSV로 저장합니다.
    - 시스템 설정을 바꾸지 않습니다. (레지스트리·정책·서비스 쓰기 없음)
    - 네트워크로 아무것도 보내지 않습니다. (외부 호출 없음)
    - 판정: 양호 / 취약 / 확인필요
    - KISA 주요정보통신기반시설 취약점 분석·평가 기준 PC 항목(PC-xx)은 원문으로 확인한 항목만 매핑하고,
      그 밖의 항목은 키트 자체 번호(EP-xx)만 사용합니다.

.PARAMETER OutputDir
    보고서를 저장할 폴더. 기본값은 현재 폴더 아래 EndpointCheck-Report.

.PARAMETER Anonymize
    보고서의 컴퓨터 이름, 사용자 이름, IP 주소를 가립니다. 외부 공유·캡처용.

.PARAMETER FailOnVulnerable
    취약 항목이 하나라도 있으면 종료 코드 1을 돌려줍니다. (기본은 0)

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\EndpointCheckKit.ps1

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\EndpointCheckKit.ps1 -Anonymize -OutputDir C:\Temp\eck

.NOTES
    License: MIT. https://github.com/kh20134/endpoint-security-checkkit
    PowerShell 5.1 이상 (Windows PowerShell 5.1 / PowerShell 7) 호환.
#>
[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path -Path (Get-Location).Path -ChildPath 'EndpointCheck-Report'),
    [switch]$Anonymize,
    [switch]$FailOnVulnerable
)

Set-StrictMode -Version 2.0
$script:EckVersion = '1.0.0'

# ---------------------------------------------------------------------------
# 판정 기준값 (키트 기본값. 조직 정책에 맞춰 조정)
# ---------------------------------------------------------------------------
$script:EckConfig = @{
    PatchGoodDays          = 35    # 마지막 OS 업데이트 설치 후 경과일: 이하 양호
    PatchBadDays           = 60    # 초과 시 취약 (그 사이는 확인필요)
    SignatureGoodDays      = 1     # 백신 엔진(시그니처) 경과일: 이하 양호
    SignatureBadDays       = 7     # 초과 시 취약
    ScreenSaverMaxSeconds  = 600   # 화면보호기·화면잠금 대기시간 상한(초)
    PasswordMinLength      = 8
    PasswordMaxAgeDays     = 90
    LockoutThresholdMax    = 10
    AdminMembersMax        = 2
    RiskyPortsVulnerable   = @(21, 23)
    RiskyPortsReview       = @(1433, 1521, 3306, 3389, 5432, 5800, 5900, 5901, 5902, 5985, 5986, 6379, 27017)
}

# Windows 11 지원 종료일 (출처: Microsoft Learn Windows 11 release information, 2026-10-29 확인)
# HomePro = Home, Pro, Pro Education, Pro for Workstations / Ent = Enterprise, Education
$script:EckWin11Lifecycle = @(
    @{ Build = 26300; Version = '26H2'; HomePro = '2028-10-10'; Ent = '2029-10-09' },
    @{ Build = 28000; Version = '26H1'; HomePro = '2028-03-14'; Ent = '2029-03-13' },
    @{ Build = 26200; Version = '25H2'; HomePro = '2027-10-12'; Ent = '2028-10-10' },
    @{ Build = 26100; Version = '24H2'; HomePro = '2026-10-13'; Ent = '2027-10-12'; Ltsc = '2029-10-09' },
    @{ Build = 22631; Version = '23H2'; HomePro = '2025-11-11'; Ent = '2026-11-10' },
    @{ Build = 22621; Version = '22H2'; HomePro = '2024-10-08'; Ent = '2025-10-14' },
    @{ Build = 22000; Version = '21H2'; HomePro = '2023-10-10'; Ent = '2024-10-08' }
)
$script:EckWin10EndDate = '2025-10-14'

# ---------------------------------------------------------------------------
# 데이터 수집 계층 (읽기 전용). 테스트에서는 이 함수들을 같은 이름으로 다시 정의해 모의(mock)함.
# ---------------------------------------------------------------------------
function Get-EckNow { Get-Date }

function Test-EckIsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-EckReg {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch { return $null }
}

function Test-EckRegKey {
    param([string]$Path)
    return (Test-Path -LiteralPath $Path)
}

function Get-EckRegValueNames {
    param([string]$Path)
    try { return @((Get-Item -LiteralPath $Path -ErrorAction Stop).GetValueNames()) } catch { return @() }
}

function Get-EckOsInfo {
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $caption = $null
    try { $caption = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption } catch { }
    return [pscustomobject]@{
        Caption        = $caption
        ProductName    = Get-EckReg $cv 'ProductName'
        EditionID      = Get-EckReg $cv 'EditionID'
        DisplayVersion = Get-EckReg $cv 'DisplayVersion'
        Build          = [int](Get-EckReg $cv 'CurrentBuildNumber')
        UBR            = Get-EckReg $cv 'UBR'
    }
}

function Get-EckHotfixes {
    try {
        return @(Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } |
            Select-Object HotFixID, Description, @{ n = 'InstalledOn'; e = { [datetime]$_.InstalledOn } })
    } catch { return @() }
}

function Get-EckDefender {
    try { return (Get-MpComputerStatus -ErrorAction Stop) } catch { return $null }
}

function Get-EckAvProducts {
    # Windows 보안 센터에 등록된 백신 제품 목록 (워크스테이션 전용 네임스페이스)
    try {
        return @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop |
            ForEach-Object { $_.displayName })
    } catch { return @() }
}

function Get-EckFirewallProfiles {
    try {
        return @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
            Select-Object Name, Enabled, DefaultInboundAction)
    } catch { return @() }
}

function Get-EckNetAccounts {
    try { return @(& net.exe accounts 2>$null) } catch { return @() }
}

function Get-EckSecPolicy {
    # 관리자 권한일 때만: 보안 정책을 임시 파일로 '내보내기'만 하고 바로 지움 (설정 변경 없음)
    if (-not (Test-EckIsAdmin)) { return $null }
    $tmp = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ('eck-' + [guid]::NewGuid().ToString('N') + '.inf')
    try {
        & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY /quiet | Out-Null
        if (-not (Test-Path -LiteralPath $tmp)) { return $null }
        $map = @{}
        foreach ($line in (Get-Content -LiteralPath $tmp -Encoding Unicode)) {
            if ($line -match '^\s*([A-Za-z]+)\s*=\s*(.+?)\s*$') { $map[$Matches[1]] = $Matches[2] }
        }
        return $map
    } catch { return $null }
    finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } }
}

function Get-EckLocalAdmins {
    try {
        return @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{ Name = $_.Name; ObjectClass = [string]$_.ObjectClass; Source = [string]$_.PrincipalSource; SID = [string]$_.SID } })
    } catch {
        try {
            $groupName = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
            $group = [ADSI]("WinNT://$env:COMPUTERNAME/$groupName,group")
            return @($group.psbase.Invoke('Members') | ForEach-Object {
                $n = $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)
                [pscustomobject]@{ Name = $n; ObjectClass = ''; Source = ''; SID = '' } })
        } catch { return $null }
    }
}

function Get-EckLocalUsers {
    try {
        return @(Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, @{ n = 'SID'; e = { [string]$_.SID } })
    } catch {
        try {
            return @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop |
                Select-Object Name, @{ n = 'Enabled'; e = { -not $_.Disabled } }, SID)
        } catch { return $null }
    }
}

function Get-EckCurrentUser {
    try { return [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { return "$env:USERDOMAIN\$env:USERNAME" }
}

function Get-EckShares {
    try {
        return @(Get-CimInstance -ClassName Win32_Share -ErrorAction Stop | Select-Object Name, Path, Type)
    } catch { return $null }
}

function Get-EckBitLocker {
    if (-not (Test-EckIsAdmin)) { return $null }
    try {
        $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        return [pscustomobject]@{ ProtectionStatus = [string]$v.ProtectionStatus; VolumeStatus = [string]$v.VolumeStatus; EncryptionPercentage = $v.EncryptionPercentage }
    } catch { return $null }
}

function Get-EckSmb1 {
    $r = [ordered]@{ ServerEnabled = $null; ClientDriverStart = $null; FeatureState = $null }
    try { $r.ServerEnabled = [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { }
    if (Test-EckIsAdmin) {
        try { $r.FeatureState = [string](Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop).State } catch { }
    }
    $r.ClientDriverStart = Get-EckReg 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start'
    if ($null -eq $r.ServerEnabled) {
        $v = Get-EckReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
        if ($null -ne $v) { $r.ServerEnabled = ([int]$v -ne 0) }
    }
    return [pscustomobject]$r
}

function Get-EckListeners {
    try {
        return @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
            $p = $null
            try { $p = (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { }
            [pscustomobject]@{ Address = [string]$_.LocalAddress; Port = [int]$_.LocalPort; Process = $p }
        })
    } catch { return $null }
}

function Get-EckVolumes {
    try {
        return @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop |
            Select-Object DeviceID, FileSystem)
    } catch { return $null }
}

function Get-EckIPv4 {
    try {
        return @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop |
            ForEach-Object { $_.IPAddress } | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
    } catch { return @() }
}

# ---------------------------------------------------------------------------
# 공통
# ---------------------------------------------------------------------------
function New-EckResult {
    param(
        [string]$Id, [string]$Kisa, [string]$Category, [string]$Item,
        [ValidateSet('양호', '취약', '확인필요')][string]$Status,
        [string]$Current, [string]$Criteria, [string]$Remediation
    )
    [pscustomobject][ordered]@{
        Id = $Id; Kisa = $Kisa; Category = $Category; Item = $Item; Status = $Status
        Current = $Current; Criteria = $Criteria; Remediation = $Remediation
    }
}

function ConvertFrom-EckNetAccounts {
    # net accounts 출력은 언어별로 라벨이 다르므로 줄 순서로 읽음
    # 순서: 강제 로그오프, 최소 사용기간, 최대 사용기간, 최소 길이, 기록 개수, 잠금 임계값, 잠금 기간, 잠금 관찰 창
    param([string[]]$Lines)
    $vals = @()
    foreach ($l in $Lines) {
        if ($l -match ':\s*(\S.*?)\s*$' -and $vals.Count -lt 8) {
            $raw = $Matches[1]
            if ($raw -match '^\d+$') { $vals += [int]$raw } else { $vals += $null }
        }
    }
    if ($vals.Count -lt 6) { return $null }
    return [pscustomobject]@{
        MinAge = $vals[1]; MaxAge = $vals[2]; MinLength = $vals[3]; History = $vals[4]; LockoutThreshold = $vals[5]
    }
}

function Get-EckOsSupport {
    param([int]$Build, [string]$EditionID, [datetime]$Now)
    $ed = [string]$EditionID
    $isLtsc = $ed -match 'EnterpriseS|IoTEnterpriseS'
    $isEnt = $ed -match '^(Enterprise|Education|ServerRdsh|IoTEnterprise)'
    if ($Build -ge 22000) {
        $row = $script:EckWin11Lifecycle | Where-Object { $_.Build -eq $Build } | Select-Object -First 1
        if (-not $row) { return @{ Known = $false; Version = "빌드 $Build"; End = $null } }
        $end = $row.HomePro
        if ($isLtsc) { if ($row.ContainsKey('Ltsc')) { $end = $row.Ltsc } else { return @{ Known = $false; Version = $row.Version; End = $null } } }
        elseif ($isEnt) { $end = $row.Ent }
        return @{ Known = $true; Version = "Windows 11 $($row.Version)"; End = [datetime]$end; Supported = ($Now.Date -le [datetime]$end) }
    }
    if ($Build -ge 10240) {
        if ($isLtsc) { return @{ Known = $false; Version = "Windows 10 LTSC (빌드 $Build)"; End = $null } }
        $end = [datetime]$script:EckWin10EndDate
        return @{ Known = $true; Version = "Windows 10 (빌드 $Build)"; End = $end; Supported = ($Now.Date -le $end); Win10 = $true }
    }
    return @{ Known = $true; Version = "빌드 $Build"; End = $null; Supported = $false }
}

# ---------------------------------------------------------------------------
# 점검 항목
# ---------------------------------------------------------------------------
function Test-EckOsSupport {
    $os = Get-EckOsInfo
    $now = Get-EckNow
    $s = Get-EckOsSupport -Build $os.Build -EditionID $os.EditionID -Now $now
    $cur = "$($os.Caption) / 에디션 $($os.EditionID) / 빌드 $($os.Build).$($os.UBR)"
    $crit = '보안 업데이트 지원 기간 안의 Windows 버전·빌드 사용'
    $fix = '지원 중인 버전으로 기능 업데이트(예: Windows 11 25H2 이상). Windows 10은 ESU 가입 여부를 확인하고 전환 일정 수립'
    if (-not $s.Known) {
        return New-EckResult 'EP-01' 'PC-11' '패치 관리' 'OS 지원 버전 사용' '확인필요' "$cur ($($s.Version), 키트 지원표에 없음)" $crit 'Microsoft Learn 수명 주기 페이지에서 해당 에디션의 지원 종료일 확인'
    }
    $endText = if ($s.End) { $s.End.ToString('yyyy-MM-dd') } else { '종료' }
    if ($s.Supported) {
        return New-EckResult 'EP-01' 'PC-11' '패치 관리' 'OS 지원 버전 사용' '양호' "$cur ($($s.Version), 지원 종료 $endText)" $crit '지원 종료일 전에 다음 버전 전환 계획 수립'
    }
    $extra = ''
    if ($s.ContainsKey('Win10') -and $s.Win10) { $extra = ' / ESU(확장 보안 업데이트) 가입 장비면 예외 처리' }
    return New-EckResult 'EP-01' 'PC-11' '패치 관리' 'OS 지원 버전 사용' '취약' "$cur ($($s.Version), 지원 종료 $endText$extra)" $crit $fix
}

function Test-EckPatchAge {
    $os = Get-EckOsInfo
    $hf = @(Get-EckHotfixes)
    $crit = "마지막 OS 업데이트 설치 후 $($script:EckConfig.PatchGoodDays)일 이내 (키트 기본값)"
    $fix = '설정 > Windows 업데이트에서 누적 업데이트 설치 후 재부팅. 조직은 WSUS·Intune 등으로 배포 상태 관리'
    if ($hf.Count -eq 0) {
        return New-EckResult 'EP-02' 'PC-10' '패치 관리' '최신 보안 업데이트 적용' '확인필요' "업데이트 설치 기록을 읽지 못함 (빌드 $($os.Build).$($os.UBR))" $crit '설정 > Windows 업데이트 > 업데이트 기록에서 최근 설치일 확인'
    }
    $last = ($hf | Sort-Object InstalledOn -Descending | Select-Object -First 1)
    $days = [int]((Get-EckNow).Date - $last.InstalledOn.Date).TotalDays
    $cur = "마지막 설치 $($last.InstalledOn.ToString('yyyy-MM-dd')) $($last.HotFixID) ($days 일 경과), 빌드 $($os.Build).$($os.UBR)"
    if ($days -le $script:EckConfig.PatchGoodDays) { return New-EckResult 'EP-02' 'PC-10' '패치 관리' '최신 보안 업데이트 적용' '양호' $cur $crit '월별 정기 업데이트(매월 둘째 주 화요일, 미국 기준) 적용 유지' }
    if ($days -le $script:EckConfig.PatchBadDays) { return New-EckResult 'EP-02' 'PC-10' '패치 관리' '최신 보안 업데이트 적용' '확인필요' $cur $crit $fix }
    return New-EckResult 'EP-02' 'PC-10' '패치 관리' '최신 보안 업데이트 적용' '취약' $cur $crit $fix
}

function Test-EckAntivirus {
    $d = Get-EckDefender
    $products = @(Get-EckAvProducts)
    $crit = "백신 설치, 엔진(시그니처) 업데이트 $($script:EckConfig.SignatureGoodDays)일 이내"
    $fix = '백신 자동 업데이트 설정 확인, 수동 업데이트 실행. Defender는 Windows 보안 > 바이러스 및 위협 방지 > 보호 업데이트'
    $plist = if ($products.Count) { ($products -join ', ') } else { '보안 센터 등록 제품 없음' }
    if ($d -and $d.AntivirusEnabled -and [string]$d.AMRunningMode -notmatch 'Passive') {
        $age = $d.AntivirusSignatureAge
        $cur = "Microsoft Defender 활성 (모드 $($d.AMRunningMode)), 시그니처 $($d.AntivirusSignatureVersion) 갱신 $(([datetime]$d.AntivirusSignatureLastUpdated).ToString('yyyy-MM-dd HH:mm')) ($age 일 경과) / 등록 제품: $plist"
        if ($age -le $script:EckConfig.SignatureGoodDays) { return New-EckResult 'EP-03' 'PC-13' '악성코드 방지' '백신 설치 및 최신 업데이트' '양호' $cur $crit '자동 업데이트 유지' }
        if ($age -le $script:EckConfig.SignatureBadDays) { return New-EckResult 'EP-03' 'PC-13' '악성코드 방지' '백신 설치 및 최신 업데이트' '확인필요' $cur $crit $fix }
        return New-EckResult 'EP-03' 'PC-13' '악성코드 방지' '백신 설치 및 최신 업데이트' '취약' $cur $crit $fix
    }
    $others = @($products | Where-Object { $_ -notmatch 'Windows Defender|Microsoft Defender' })
    if ($others.Count -gt 0) {
        return New-EckResult 'EP-03' 'PC-13' '악성코드 방지' '백신 설치 및 최신 업데이트' '확인필요' "타사 백신 등록: $($others -join ', ') (엔진 날짜는 제품 콘솔에서 확인)" $crit '해당 백신 관리 콘솔에서 엔진 업데이트 일자와 실시간 감시 상태 확인'
    }
    return New-EckResult 'EP-03' 'PC-13' '악성코드 방지' '백신 설치 및 최신 업데이트' '취약' "활성 백신을 찾지 못함 / 등록 제품: $plist" $crit '조직 표준 백신(EDR) 설치 또는 Microsoft Defender 활성화'
}

function Test-EckRealtime {
    $d = Get-EckDefender
    $crit = '백신 실시간 감시 사용'
    if ($d -and $d.AntivirusEnabled -and [string]$d.AMRunningMode -notmatch 'Passive') {
        if ($d.RealTimeProtectionEnabled) { return New-EckResult 'EP-04' 'PC-14' '악성코드 방지' '백신 실시간 감시' '양호' 'Defender 실시간 보호 켜짐' $crit '실시간 보호 끄기 권한을 사용자에게 주지 않음(변조 방지 사용)' }
        return New-EckResult 'EP-04' 'PC-14' '악성코드 방지' '백신 실시간 감시' '취약' 'Defender 실시간 보호 꺼짐' $crit 'Windows 보안 > 바이러스 및 위협 방지 설정 > 실시간 보호 켬, 변조 방지 켬'
    }
    $others = @(Get-EckAvProducts | Where-Object { $_ -notmatch 'Windows Defender|Microsoft Defender' })
    if ($others.Count -gt 0) { return New-EckResult 'EP-04' 'PC-14' '악성코드 방지' '백신 실시간 감시' '확인필요' "타사 백신 사용: $($others -join ', ')" $crit '해당 제품 콘솔에서 실시간 감시 상태 확인' }
    return New-EckResult 'EP-04' 'PC-14' '악성코드 방지' '백신 실시간 감시' '취약' '실시간 감시 백신 없음' $crit '백신 설치 후 실시간 감시 사용'
}

function Test-EckFirewall {
    $p = @(Get-EckFirewallProfiles)
    $crit = '도메인·개인·공용 프로필 모두 방화벽 사용'
    if ($p.Count -eq 0) { return New-EckResult 'EP-05' 'PC-15' '네트워크 보호' 'Windows 방화벽 사용' '확인필요' '방화벽 상태를 읽지 못함 (타사 방화벽 여부 확인)' $crit 'Windows 보안 > 방화벽 및 네트워크 보호에서 상태 확인' }
    $off = @($p | Where-Object { -not ([string]$_.Enabled -in @('True', '1')) })
    $cur = ($p | ForEach-Object { "$($_.Name)=$(if ([string]$_.Enabled -in @('True','1')) { '켜짐' } else { '꺼짐' })" }) -join ', '
    if ($off.Count -eq 0) { return New-EckResult 'EP-05' 'PC-15' '네트워크 보호' 'Windows 방화벽 사용' '양호' $cur $crit '인바운드 허용 규칙을 정기 검토' }
    return New-EckResult 'EP-05' 'PC-15' '네트워크 보호' 'Windows 방화벽 사용' '취약' $cur $crit '제어판 > Windows Defender 방화벽 > 방화벽 켜기/끄기에서 모든 프로필 사용. 조직은 GPO로 강제'
}

function Test-EckScreenLock {
    $polU = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
    $usr = 'HKCU:\Control Panel\Desktop'
    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $max = $script:EckConfig.ScreenSaverMaxSeconds
    $crit = "화면보호기(또는 화면잠금) $([int]($max/60))분 이내 + 해제 시 암호 (키트 기본값)"
    $inactivity = Get-EckReg $sys 'InactivityTimeoutSecs'
    if ($null -ne $inactivity -and [int]$inactivity -gt 0 -and [int]$inactivity -le $max) {
        return New-EckResult 'EP-06' 'PC-16' '접근 통제' '화면보호기·자동 잠금' '양호' "컴퓨터 비활성 한도(InactivityTimeoutSecs) $inactivity 초" $crit '정책 유지'
    }
    $active = Get-EckReg $polU 'ScreenSaveActive'; if ($null -eq $active) { $active = Get-EckReg $usr 'ScreenSaveActive' }
    $secure = Get-EckReg $polU 'ScreenSaverIsSecure'; if ($null -eq $secure) { $secure = Get-EckReg $usr 'ScreenSaverIsSecure' }
    $timeout = Get-EckReg $polU 'ScreenSaveTimeOut'; if ($null -eq $timeout) { $timeout = Get-EckReg $usr 'ScreenSaveTimeOut' }
    $nv = { param($x) if ($null -eq $x -or [string]$x -eq '') { '설정 없음' } else { [string]$x } }
    $cur = "화면보호기 사용=$(& $nv $active), 암호 보호=$(& $nv $secure), 대기=$(& $nv $timeout)$(if ($timeout) { ' 초' })"
    if ($null -ne $inactivity) { $cur += ", 비활성 한도=$inactivity 초" }
    $fix = "설정 > 개인 설정 > 잠금 화면 > 화면 보호기: 대기 $([int]($max/60))분 이하, '다시 시작할 때 로그온 화면 표시' 선택. 조직은 GPO(사용자 구성 > 관리 템플릿 > 제어판 > 개인 설정) 또는 '대화형 로그온: 컴퓨터 비활성 한도'로 강제"
    if ([string]$active -eq '1' -and [string]$secure -eq '1' -and $timeout -and [int]$timeout -gt 0 -and [int]$timeout -le $max) {
        return New-EckResult 'EP-06' 'PC-16' '접근 통제' '화면보호기·자동 잠금' '양호' $cur $crit '정책 유지'
    }
    return New-EckResult 'EP-06' 'PC-16' '접근 통제' '화면보호기·자동 잠금' '취약' $cur $crit $fix
}

function Get-EckPasswordPolicy {
    $na = ConvertFrom-EckNetAccounts -Lines (Get-EckNetAccounts)
    $sp = Get-EckSecPolicy
    return @{ Net = $na; Sec = $sp }
}

function Test-EckPasswordMaxAge {
    param($Policy = (Get-EckPasswordPolicy))
    $max = $script:EckConfig.PasswordMaxAgeDays
    $crit = "최대 암호 사용 기간 1~$max 일"
    if (-not $Policy.Net) { return New-EckResult 'EP-07' 'PC-01' '계정 관리' '비밀번호 주기적 변경' '확인필요' 'net accounts 결과를 읽지 못함' $crit 'secpol.msc > 계정 정책 > 암호 정책 확인' }
    $v = $Policy.Net.MaxAge
    $fix = "secpol.msc > 계정 정책 > 암호 정책 > 최대 암호 사용 기간 $max 일 이하. Microsoft 계정·Entra ID 계정은 해당 정책(Intune 등)에서 관리"
    if ($null -eq $v) { return New-EckResult 'EP-07' 'PC-01' '계정 관리' '비밀번호 주기적 변경' '취약' '최대 암호 사용 기간: 제한 없음' $crit $fix }
    if ($v -ge 1 -and $v -le $max) { return New-EckResult 'EP-07' 'PC-01' '계정 관리' '비밀번호 주기적 변경' '양호' "최대 암호 사용 기간: $v 일" $crit '정책 유지' }
    return New-EckResult 'EP-07' 'PC-01' '계정 관리' '비밀번호 주기적 변경' '취약' "최대 암호 사용 기간: $v 일" $crit $fix
}

function Test-EckPasswordPolicy {
    param($Policy = (Get-EckPasswordPolicy))
    $minLen = $script:EckConfig.PasswordMinLength
    $crit = "최소 암호 길이 $minLen 자 이상, 복잡성 사용"
    $fix = "secpol.msc > 계정 정책 > 암호 정책: 최소 암호 길이 $minLen 이상, '암호는 복잡성을 만족해야 함' 사용"
    if (-not $Policy.Net) { return New-EckResult 'EP-08' 'PC-02' '계정 관리' '비밀번호 관리 정책' '확인필요' 'net accounts 결과를 읽지 못함' $crit $fix }
    $len = if ($null -eq $Policy.Net.MinLength) { 0 } else { $Policy.Net.MinLength }
    $cx = $null
    if ($Policy.Sec -and $Policy.Sec.ContainsKey('PasswordComplexity')) { $cx = [string]$Policy.Sec['PasswordComplexity'] }
    $cxText = if ($cx -eq '1') { '사용' } elseif ($cx -eq '0') { '사용 안 함' } else { '확인 불가(관리자 권한 필요)' }
    $cur = "최소 길이 $len 자, 복잡성 $cxText"
    if ($len -lt $minLen -or $cx -eq '0') { return New-EckResult 'EP-08' 'PC-02' '계정 관리' '비밀번호 관리 정책' '취약' $cur $crit $fix }
    if ($null -eq $cx) { return New-EckResult 'EP-08' 'PC-02' '계정 관리' '비밀번호 관리 정책' '확인필요' $cur $crit '관리자 권한 PowerShell로 다시 실행해 복잡성 설정 확인' }
    return New-EckResult 'EP-08' 'PC-02' '계정 관리' '비밀번호 관리 정책' '양호' $cur $crit '정책 유지'
}

function Test-EckLockout {
    param($Policy = (Get-EckPasswordPolicy))
    $mx = $script:EckConfig.LockoutThresholdMax
    $crit = "계정 잠금 임계값 1~$mx 회 (키트 기본값)"
    $fix = "secpol.msc > 계정 정책 > 계정 잠금 정책 > 계정 잠금 임계값 $mx 회 이하"
    if (-not $Policy.Net) { return New-EckResult 'EP-09' '' '계정 관리' '계정 잠금 임계값' '확인필요' 'net accounts 결과를 읽지 못함' $crit $fix }
    $v = $Policy.Net.LockoutThreshold
    if ($null -eq $v -or $v -eq 0) { return New-EckResult 'EP-09' '' '계정 관리' '계정 잠금 임계값' '취약' '계정 잠금 임계값: 사용 안 함' $crit $fix }
    if ($v -le $mx) { return New-EckResult 'EP-09' '' '계정 관리' '계정 잠금 임계값' '양호' "계정 잠금 임계값: $v 회" $crit '정책 유지' }
    return New-EckResult 'EP-09' '' '계정 관리' '계정 잠금 임계값' '취약' "계정 잠금 임계값: $v 회" $crit $fix
}

function Test-EckAutoLogon {
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $auto = [string](Get-EckReg $k 'AutoAdminLogon')
    $hasPw = (Get-EckRegValueNames $k) -contains 'DefaultPassword'   # 값은 읽지 않고 존재 여부만 확인
    $crit = 'AutoAdminLogon 사용 안 함, DefaultPassword 저장 없음'
    $cur = "AutoAdminLogon=$(if ($auto) { $auto } else { '없음' }), DefaultPassword 값 $(if ($hasPw) { '있음' } else { '없음' })"
    $fix = 'netplwiz에서 자동 로그인 해제, 레지스트리 Winlogon의 DefaultPassword 값 삭제(관리자 확인 후)'
    if ($auto -eq '1' -or $hasPw) { return New-EckResult 'EP-10' 'PC-12' '계정 관리' '자동 로그온 금지' '취약' $cur $crit $fix }
    return New-EckResult 'EP-10' 'PC-12' '계정 관리' '자동 로그온 금지' '양호' $cur $crit '정책 유지'
}

function Test-EckGuest {
    $u = Get-EckLocalUsers
    $crit = 'Guest 계정 사용 안 함'
    if ($null -eq $u) { return New-EckResult 'EP-11' '' '계정 관리' 'Guest 계정 비활성화' '확인필요' '로컬 계정 목록을 읽지 못함' $crit 'lusrmgr.msc에서 Guest 상태 확인' }
    $g = @($u | Where-Object { [string]$_.SID -match '-501$' })
    if ($g.Count -eq 0) { return New-EckResult 'EP-11' '' '계정 관리' 'Guest 계정 비활성화' '양호' 'Guest(RID 501) 계정 없음' $crit '정책 유지' }
    if ($g[0].Enabled) { return New-EckResult 'EP-11' '' '계정 관리' 'Guest 계정 비활성화' '취약' 'Guest(RID 501) 계정 사용 중' $crit 'lusrmgr.msc > 사용자 > Guest > 계정 사용 안 함' }
    return New-EckResult 'EP-11' '' '계정 관리' 'Guest 계정 비활성화' '양호' 'Guest(RID 501) 계정 사용 안 함' $crit '정책 유지'
}

function Test-EckLocalAdmins {
    $m = Get-EckLocalAdmins
    $me = Get-EckCurrentUser
    $mx = $script:EckConfig.AdminMembersMax
    $crit = "Administrators 그룹 구성원 최소화($mx 명 이하), 일상 업무 계정은 표준 사용자"
    $fix = '일상 업무용 계정은 표준 사용자로 바꾸고, 관리 작업은 별도 관리자 계정 또는 LAPS 관리 계정 사용'
    if ($null -eq $m) { return New-EckResult 'EP-12' '' '계정 관리' '관리자 그룹 최소화' '확인필요' 'Administrators 구성원을 읽지 못함' $crit 'lusrmgr.msc > 그룹 > Administrators 확인' }
    $names = @($m | ForEach-Object { $_.Name })
    $meIn = @($names | Where-Object { $_ -eq $me -or $_.Split('\')[-1] -eq $me.Split('\')[-1] }).Count -gt 0
    $cur = "구성원 $($names.Count) 명: $($names -join ', ')"
    if ($meIn) { $cur += ' / 현재 사용자 포함' }
    if ($names.Count -gt $mx -or $meIn) { return New-EckResult 'EP-12' '' '계정 관리' '관리자 그룹 최소화' '확인필요' $cur $crit $fix }
    return New-EckResult 'EP-12' '' '계정 관리' '관리자 그룹 최소화' '양호' $cur $crit '분기별 구성원 검토'
}

function Test-EckShares {
    $s = Get-EckShares
    $crit = '업무상 필요 없는 공유 폴더 없음 (기본 관리 공유 C$·ADMIN$·IPC$ 제외)'
    $fix = '컴퓨터 관리(compmgmt.msc) > 공유 폴더 > 공유에서 불필요한 공유 해제. 필요 시 Everyone 권한 제거, 특정 사용자만 허용'
    if ($null -eq $s) { return New-EckResult 'EP-13' 'PC-04' '데이터 보호' '공유 폴더 제거' '확인필요' '공유 목록을 읽지 못함' $crit $fix }
    $user = @($s | Where-Object { [int64]$_.Type -eq 0 -and $_.Name -notmatch '^[A-Za-z]\$$' -and $_.Name -ne 'ADMIN$' -and $_.Name -ne 'print$' })
    if ($user.Count -eq 0) { return New-EckResult 'EP-13' 'PC-04' '데이터 보호' '공유 폴더 제거' '양호' '사용자 생성 공유 없음' $crit '정기 확인' }
    $visible = @($user | Where-Object { $_.Name -notmatch '\$$' })
    $cur = '사용자 공유: ' + (($user | ForEach-Object { "$($_.Name)($($_.Path))" }) -join ', ')
    if ($visible.Count -gt 0) { return New-EckResult 'EP-13' 'PC-04' '데이터 보호' '공유 폴더 제거' '취약' $cur $crit $fix }
    return New-EckResult 'EP-13' 'PC-04' '데이터 보호' '공유 폴더 제거' '확인필요' $cur $crit $fix
}

function Test-EckAutorun {
    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer')
    $crit = '모든 드라이브 자동 실행 끔 (NoDriveTypeAutoRun=0xFF 또는 NoAutorun=1)'
    $vals = @()
    $ok = $false
    foreach ($p in $paths) {
        $nd = Get-EckReg $p 'NoDriveTypeAutoRun'; $na = Get-EckReg $p 'NoAutorun'
        $hive = $p.Substring(0, 4)
        if ($null -ne $nd) { $vals += "$hive NoDriveTypeAutoRun=0x{0:X}" -f [int]$nd; if ([int]$nd -eq 255) { $ok = $true } }
        if ($null -ne $na) { $vals += "$hive NoAutorun=$na"; if ([int]$na -eq 1) { $ok = $true } }
    }
    $ap = Get-EckReg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' 'DisableAutoplay'
    if ($null -ne $ap) { $vals += "DisableAutoplay=$ap" }
    $cur = if ($vals.Count) { $vals -join ', ' } else { '자동 실행 정책 없음 (Windows 기본값)' }
    if ($ok) { return New-EckResult 'EP-14' 'PC-17' '매체 보안' '이동식 미디어 자동 실행 방지' '양호' $cur $crit '정책 유지' }
    return New-EckResult 'EP-14' 'PC-17' '매체 보안' '이동식 미디어 자동 실행 방지' '취약' $cur $crit "gpedit.msc > 컴퓨터 구성 > 관리 템플릿 > Windows 구성 요소 > 자동 실행 정책 > '자동 실행 끄기' 사용, 대상 '모든 드라이브'"
}

function Test-EckUsbStorage {
    $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
    $rd = "$base\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
    $crit = '이동식 저장장치 쓰기(또는 전체) 통제 정책 적용, 또는 매체제어 솔루션 사용'
    $found = @()
    if ([string](Get-EckReg $base 'Deny_All') -eq '1') { $found += '모든 이동식 저장소 액세스 거부' }
    if ([string](Get-EckReg $rd 'Deny_Write') -eq '1') { $found += '이동식 디스크 쓰기 거부' }
    if ([string](Get-EckReg $rd 'Deny_Read') -eq '1') { $found += '이동식 디스크 읽기 거부' }
    $usb = Get-EckReg 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' 'Start'
    if ($null -ne $usb -and [int]$usb -eq 4) { $found += 'USBSTOR 드라이버 사용 안 함(Start=4)' }
    if ($found.Count) { return New-EckResult 'EP-15' 'PC-17' '매체 보안' 'USB 저장장치 통제' '양호' ($found -join ', ') $crit '예외 승인 절차와 반출입 기록 유지' }
    $cur = "Windows 정책 통제 없음 (USBSTOR Start=$usb)"
    return New-EckResult 'EP-15' 'PC-17' '매체 보안' 'USB 저장장치 통제' '확인필요' $cur $crit "매체제어(DLP) 솔루션 사용 여부 확인. 없으면 gpedit.msc > 컴퓨터 구성 > 관리 템플릿 > 시스템 > 이동식 저장소 액세스 > '이동식 디스크: 쓰기 권한 거부' 사용"
}

function Test-EckBitLocker {
    $b = Get-EckBitLocker
    $crit = '시스템 드라이브 BitLocker(또는 장치 암호화) 보호 켜짐'
    if ($null -eq $b) {
        $why = if (Test-EckIsAdmin) { 'BitLocker 상태를 읽지 못함 (Home 에디션이면 설정 > 개인 정보 및 보안 > 장치 암호화 확인)' } else { '관리자 권한이 아니어서 확인 불가' }
        return New-EckResult 'EP-16' '' '데이터 보호' '디스크 암호화(BitLocker)' '확인필요' $why $crit '관리자 PowerShell로 다시 실행하거나 제어판 > BitLocker 드라이브 암호화에서 확인'
    }
    $cur = "$env:SystemDrive 보호=$($b.ProtectionStatus), 상태=$($b.VolumeStatus), 암호화 $($b.EncryptionPercentage)%"
    if ($b.ProtectionStatus -eq 'On') { return New-EckResult 'EP-16' '' '데이터 보호' '디스크 암호화(BitLocker)' '양호' $cur $crit '복구 키를 AD·Entra ID 또는 별도 보관소에 백업했는지 확인' }
    return New-EckResult 'EP-16' '' '데이터 보호' '디스크 암호화(BitLocker)' '취약' $cur $crit '제어판 > BitLocker 드라이브 암호화 > BitLocker 켜기. 복구 키 백업 후 진행'
}

function Test-EckRdp {
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $pk = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $deny = Get-EckReg $pk 'fDenyTSConnections'; $src = '정책'
    if ($null -eq $deny) { $deny = Get-EckReg $k 'fDenyTSConnections'; $src = '로컬' }
    $nla = Get-EckReg "$k\WinStations\RDP-Tcp" 'UserAuthentication'
    $crit = '원격 데스크톱 사용 안 함. 업무상 필요 시 NLA 사용, 허용 대상·출발지 IP 제한'
    if ($null -eq $deny -or [int]$deny -eq 1) { return New-EckResult 'EP-17' '' '원격 접속' '원격 데스크톱(RDP) 제한' '양호' "원격 데스크톱 꺼짐 ($src)" $crit '정책 유지' }
    $cur = "원격 데스크톱 켜짐 ($src), NLA=$nla"
    if ([string]$nla -eq '1') { return New-EckResult 'EP-17' '' '원격 접속' '원격 데스크톱(RDP) 제한' '확인필요' $cur $crit '업무 필요성 확인. 불필요 시 설정 > 시스템 > 원격 데스크톱 끔. 필요 시 방화벽에서 출발지 IP 제한' }
    return New-EckResult 'EP-17' '' '원격 접속' '원격 데스크톱(RDP) 제한' '취약' $cur $crit '원격 데스크톱 끔. 사용해야 하면 NLA(네트워크 수준 인증) 필수 설정'
}

function Test-EckRemoteAssistance {
    $pk = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
    $v = Get-EckReg $pk 'fAllowToGetHelp'; $src = '정책'
    if ($null -eq $v) { $v = Get-EckReg $k 'fAllowToGetHelp'; $src = '로컬' }
    $crit = "'이 컴퓨터에 대한 원격 지원 연결 허용' 해제"
    if ($null -ne $v -and [int]$v -eq 0) { return New-EckResult 'EP-18' 'PC-18' '원격 접속' '원격 지원 금지' '양호' "원격 지원 허용 안 함 ($src)" $crit '정책 유지' }
    $cur = if ($null -eq $v) { '설정값 없음' } else { "원격 지원 허용 ($src, fAllowToGetHelp=$v)" }
    return New-EckResult 'EP-18' 'PC-18' '원격 접속' '원격 지원 금지' '취약' $cur $crit "시스템 속성(sysdm.cpl) > 원격 > '이 컴퓨터에 대한 원격 지원 연결 허용' 해제. 조직은 GPO '원격 지원 요청'을 사용 안 함으로 설정"
}

function Test-EckSmb1 {
    $s = Get-EckSmb1
    $crit = 'SMBv1 서버·클라이언트 사용 안 함'
    $parts = @()
    if ($null -ne $s.FeatureState) { $parts += "기능=$($s.FeatureState)" }
    if ($null -ne $s.ServerEnabled) { $parts += "서버 SMB1=$(if ($s.ServerEnabled) { '사용' } else { '사용 안 함' })" }
    $parts += "클라이언트 드라이버(mrxsmb10)=$(if ($null -eq $s.ClientDriverStart) { '없음' } else { "Start $($s.ClientDriverStart)" })"
    $cur = $parts -join ', '
    $fix = "제어판 > Windows 기능 켜기/끄기 > 'SMB 1.0/CIFS 파일 공유 지원' 해제 후 재부팅"
    $clientOn = ($null -ne $s.ClientDriverStart -and [int]$s.ClientDriverStart -ne 4)
    if ($s.ServerEnabled -eq $true -or $clientOn -or [string]$s.FeatureState -eq 'Enabled') { return New-EckResult 'EP-19' '' '네트워크 보호' 'SMBv1 비활성화' '취약' $cur $crit $fix }
    if ($null -eq $s.ServerEnabled -and $null -eq $s.FeatureState) { return New-EckResult 'EP-19' '' '네트워크 보호' 'SMBv1 비활성화' '확인필요' $cur $crit '관리자 PowerShell로 다시 실행해 서버 측 SMB1 상태 확인' }
    return New-EckResult 'EP-19' '' '네트워크 보호' 'SMBv1 비활성화' '양호' $cur $crit '정책 유지'
}

function Test-EckListeningPorts {
    $l = Get-EckListeners
    $crit = '외부에 열린 평문·원격관리·DB 포트 없음 (루프백 제외)'
    if ($null -eq $l) { return New-EckResult 'EP-20' '' '네트워크 보호' '위험 포트 대기 여부' '확인필요' '대기 포트 목록을 읽지 못함' $crit 'netstat -ano 로 수동 확인' }
    $ext = @($l | Where-Object { $_.Address -notin @('127.0.0.1', '::1') })
    $bad = @($ext | Where-Object { $script:EckConfig.RiskyPortsVulnerable -contains $_.Port })
    $rev = @($ext | Where-Object { $script:EckConfig.RiskyPortsReview -contains $_.Port })
    $fmt = { param($x) (($x | Sort-Object Port -Unique | ForEach-Object { "$($_.Port)/$(if ($_.Process) { $_.Process } else { '?' })" }) -join ', ') }
    $fix = '불필요한 서비스 중지·제거. 필요한 서비스는 Windows 방화벽에서 허용 출발지를 업무망으로 제한'
    if ($bad.Count) { return New-EckResult 'EP-20' '' '네트워크 보호' '위험 포트 대기 여부' '취약' ("평문 프로토콜 대기: " + (& $fmt $bad) + $(if ($rev.Count) { " / 검토 대상: " + (& $fmt $rev) } else { '' })) $crit $fix }
    if ($rev.Count) { return New-EckResult 'EP-20' '' '네트워크 보호' '위험 포트 대기 여부' '확인필요' ("검토 대상 포트 대기: " + (& $fmt $rev)) $crit $fix }
    return New-EckResult 'EP-20' '' '네트워크 보호' '위험 포트 대기 여부' '양호' "외부 대기 포트 $(@($ext | Sort-Object Port -Unique).Count) 개, 키트 위험 목록 해당 없음" $crit '정기 확인'
}

function Test-EckNtfs {
    $v = Get-EckVolumes
    $crit = '고정 디스크 파일 시스템 NTFS(또는 ReFS)'
    if ($null -eq $v) { return New-EckResult 'EP-21' 'PC-07' '데이터 보호' 'NTFS 파일 시스템 사용' '확인필요' '볼륨 정보를 읽지 못함' $crit 'diskmgmt.msc에서 파일 시스템 확인' }
    $cur = ($v | ForEach-Object { "$($_.DeviceID) $($_.FileSystem)" }) -join ', '
    $bad = @($v | Where-Object { $_.FileSystem -and $_.FileSystem -notin @('NTFS', 'ReFS') })
    if ($bad.Count) { return New-EckResult 'EP-21' 'PC-07' '데이터 보호' 'NTFS 파일 시스템 사용' '취약' $cur $crit '데이터 백업 후 convert 드라이브: /fs:ntfs 로 변환(관리자 판단 하에 별도 작업)' }
    return New-EckResult 'EP-21' 'PC-07' '데이터 보호' 'NTFS 파일 시스템 사용' '양호' $cur $crit '정책 유지'
}

$script:EckChecks = @(
    'Test-EckOsSupport', 'Test-EckPatchAge', 'Test-EckAntivirus', 'Test-EckRealtime', 'Test-EckFirewall',
    'Test-EckScreenLock', 'Test-EckPasswordMaxAge', 'Test-EckPasswordPolicy', 'Test-EckLockout', 'Test-EckAutoLogon',
    'Test-EckGuest', 'Test-EckLocalAdmins', 'Test-EckShares', 'Test-EckAutorun', 'Test-EckUsbStorage',
    'Test-EckBitLocker', 'Test-EckRdp', 'Test-EckRemoteAssistance', 'Test-EckSmb1', 'Test-EckListeningPorts', 'Test-EckNtfs'
)

function Invoke-EckChecks {
    $policy = $null
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($name in $script:EckChecks) {
        try {
            if ($name -in @('Test-EckPasswordMaxAge', 'Test-EckPasswordPolicy', 'Test-EckLockout')) {
                if ($null -eq $policy) { $policy = Get-EckPasswordPolicy }
                $r = & $name -Policy $policy
            } else { $r = & $name }
            $results.Add($r)
        } catch {
            $results.Add((New-EckResult ('EP-{0:D2}' -f ([array]::IndexOf($script:EckChecks, $name) + 1)) '' '오류' $name '확인필요' ("점검 중 오류: " + $_.Exception.Message) '' '관리자 권한 또는 수동 확인'))
        }
    }
    return $results.ToArray()
}

# ---------------------------------------------------------------------------
# 마스킹·보고서
# ---------------------------------------------------------------------------
function Protect-EckText {
    param([string]$Text, [string[]]$Secrets)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text
    foreach ($s in ($Secrets | Where-Object { $_ -and $_.Length -ge 2 } | Sort-Object Length -Descending)) {
        $t = [regex]::Replace($t, [regex]::Escape($s), $(if ($s -match '^[0-9.]+$') { 'x.x.x.x' } else { '***' }), 'IgnoreCase')
    }
    return $t
}

function Get-EckSecrets {
    $list = @($env:COMPUTERNAME, $env:USERNAME, $env:USERDOMAIN) + @(Get-EckIPv4)
    $me = Get-EckCurrentUser
    if ($me) { $list += $me; $list += $me.Split('\') }
    $users = Get-EckLocalUsers
    if ($users) { $list += @($users | Where-Object { [string]$_.SID -match "-\d{4,}$" } | ForEach-Object { $_.Name }) }
    $admins = Get-EckLocalAdmins
    if ($admins) { $list += @($admins | Where-Object { [string]$_.SID -match "-\d{4,}$" } | ForEach-Object { $_.Name; $_.Name.Split("\")[-1] }) }
    return @($list | Where-Object { $_ } | Select-Object -Unique)
}

function ConvertTo-EckHtmlText { param([string]$s) if ($null -eq $s) { return '' } return [System.Net.WebUtility]::HtmlEncode($s) }

function New-EckHtmlReport {
    param([object[]]$Results, [hashtable]$Meta)
    $e = { param($x) ConvertTo-EckHtmlText $x }
    $count = @{ '양호' = 0; '취약' = 0; '확인필요' = 0 }
    foreach ($r in $Results) { $count[$r.Status]++ }
    $rows = foreach ($r in $Results) {
        $cls = switch ($r.Status) { '양호' { 'ok' } '취약' { 'bad' } default { 'chk' } }
        $kisa = if ($r.Kisa) { & $e $r.Kisa } else { '-' }
        "<tr class='$cls'><td>$(& $e $r.Id)</td><td>$kisa</td><td>$(& $e $r.Category)</td><td>$(& $e $r.Item)</td><td><span class='b $cls'>$(& $e $r.Status)</span></td><td>$(& $e $r.Current)</td><td>$(& $e $r.Criteria)</td><td>$(& $e $r.Remediation)</td></tr>"
    }
    $metaRows = ($Meta.Keys | Sort-Object | ForEach-Object { "<tr><th>$(& $e $_)</th><td>$(& $e ([string]$Meta[$_]))</td></tr>" }) -join "`n"
    return @"
<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>엔드포인트 보안 점검 보고서</title>
<style>
body{font-family:'Malgun Gothic','Noto Sans KR','Noto Sans CJK KR',sans-serif;margin:0;padding:16px;background:#f5f7fa;color:#1f2933;font-size:14px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:24px 0 8px}.sub{color:#52606d;margin:0 0 16px}
.cards{display:flex;gap:8px;flex-wrap:wrap}.card{flex:1;min-width:90px;background:#fff;border-radius:8px;padding:12px;border-top:4px solid #9aa5b1}
.card b{display:block;font-size:24px}.card.ok{border-color:#2f9e44}.card.bad{border-color:#e03131}.card.chk{border-color:#f08c00}
table{width:100%;border-collapse:collapse;background:#fff}th,td{border:1px solid #d9e2ec;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#e4e7eb}.b{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;font-weight:bold;white-space:nowrap}
.b.ok{background:#2f9e44}.b.bad{background:#e03131}.b.chk{background:#f08c00}.wrap{overflow-x:auto}
.note{color:#52606d;font-size:12px;margin-top:16px}.res td:first-child,.res td:nth-child(2),.res td:nth-child(3){white-space:nowrap}@media (max-width:760px){.res{min-width:820px}}
</style></head><body>
<h1>엔드포인트 보안 점검 보고서</h1>
<p class="sub">Endpoint Security Check Kit v$($script:EckVersion) · 읽기 전용 점검 · 점검 시각 $(& $e $Meta['점검 시각'])</p>
<div class="cards">
<div class="card"><span>전체</span><b>$($Results.Count)</b></div>
<div class="card ok"><span>양호</span><b>$($count['양호'])</b></div>
<div class="card bad"><span>취약</span><b>$($count['취약'])</b></div>
<div class="card chk"><span>확인필요</span><b>$($count['확인필요'])</b></div>
</div>
<h2>점검 대상</h2>
<div class="wrap"><table>$metaRows</table></div>
<h2>점검 결과</h2>
<div class="wrap"><table class="res">
<thead><tr><th>ID</th><th>KISA</th><th>분류</th><th>항목</th><th>결과</th><th>현재 상태</th><th>판단 기준</th><th>조치 방법</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table></div>
<p class="note">KISA 열은 주요정보통신기반시설 취약점 분석·평가 기준(PC 항목) 번호이며, 빈 칸(-)은 키트 자체 항목임. 판단 기준 중 '키트 기본값'은 조직 정책에 맞춰 스크립트 상단 설정에서 조정. 이 보고서는 설정값을 읽어 만든 것으로 침투 시험 결과가 아님.</p>
</body></html>
"@
}

function Invoke-EckMain {
    $now = Get-EckNow
    $os = Get-EckOsInfo
    $isAdmin = Test-EckIsAdmin
    Write-Host "Endpoint Security Check Kit v$($script:EckVersion) - 읽기 전용 점검 시작 (관리자 권한: $isAdmin)"
    $results = Invoke-EckChecks
    $meta = [ordered]@{
        '점검 시각'   = $now.ToString('yyyy-MM-dd HH:mm:ss') + ' (PC 로컬 시간)'
        '컴퓨터 이름' = $env:COMPUTERNAME
        '사용자'      = Get-EckCurrentUser
        'IP 주소'     = ((Get-EckIPv4) -join ', ')
        '운영체제'    = "$($os.Caption) $($os.DisplayVersion) (빌드 $($os.Build).$($os.UBR), 에디션 $($os.EditionID))"
        '관리자 권한' = $(if ($isAdmin) { '예' } else { '아니오 (일부 항목 확인필요로 표시)' })
    }
    $tag = $env:COMPUTERNAME
    if ($Anonymize) {
        $secrets = Get-EckSecrets
        foreach ($r in $results) {
            $r.Current = Protect-EckText $r.Current $secrets
        }
        $keys = @($meta.Keys)
        foreach ($k in $keys) { $meta[$k] = Protect-EckText ([string]$meta[$k]) $secrets }
        $meta['컴퓨터 이름'] = 'PC-****'; $meta['사용자'] = '***'; $meta['IP 주소'] = 'x.x.x.x'
        $tag = 'masked'
    }
    $h = @{}; foreach ($k in $meta.Keys) { $h[$k] = $meta[$k] }
    if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $stamp = $now.ToString('yyyyMMdd-HHmmss')
    $htmlPath = Join-Path $OutputDir "endpoint-check-$tag-$stamp.html"
    $csvPath = Join-Path $OutputDir "endpoint-check-$tag-$stamp.csv"
    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    [IO.File]::WriteAllText($htmlPath, (New-EckHtmlReport -Results $results -Meta $h), $utf8Bom)
    $csv = $results | Select-Object @{ n = 'ID'; e = { $_.Id } }, @{ n = 'KISA'; e = { $_.Kisa } }, @{ n = '분류'; e = { $_.Category } },
        @{ n = '항목'; e = { $_.Item } }, @{ n = '결과'; e = { $_.Status } }, @{ n = '현재 상태'; e = { $_.Current } },
        @{ n = '판단 기준'; e = { $_.Criteria } }, @{ n = '조치 방법'; e = { $_.Remediation } } | ConvertTo-Csv -NoTypeInformation
    [IO.File]::WriteAllLines($csvPath, [string[]]$csv, $utf8Bom)
    foreach ($r in $results) {
        $color = switch ($r.Status) { '양호' { 'Green' } '취약' { 'Red' } default { 'Yellow' } }
        Write-Host ("[{0}] {1,-6} {2}" -f $r.Status, $r.Id, $r.Item) -ForegroundColor $color
    }
    $bad = @($results | Where-Object { $_.Status -eq '취약' }).Count
    $chk = @($results | Where-Object { $_.Status -eq '확인필요' }).Count
    Write-Host ("결과: 전체 {0} / 양호 {1} / 취약 {2} / 확인필요 {3}" -f $results.Count, ($results.Count - $bad - $chk), $bad, $chk)
    Write-Host "HTML: $htmlPath"
    Write-Host "CSV : $csvPath"
    if ($FailOnVulnerable -and $bad -gt 0) { return 1 }
    return 0
}

if ($MyInvocation.InvocationName -ne '.') {
    $code = Invoke-EckMain
    exit $code
}

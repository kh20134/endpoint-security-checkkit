<#
  의존성 없는 테스트 러너 (Windows PowerShell 5.1 / PowerShell 7 공통).
  실제 PC 상태를 읽지 않도록 데이터 수집 함수를 모의(mock) 함수로 바꿔 끼운 뒤 판정 로직만 검사함.
  실행: powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\EndpointCheckKit.Tests.ps1
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $root 'src/EndpointCheckKit.ps1'

# 1) 구문 검사
$tokens = $null; $errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors) | Out-Null
$script:Pass = 0; $script:Fail = 0
function Assert-True([bool]$Cond, [string]$Name) {
    if ($Cond) { $script:Pass++; Write-Host "  PASS $Name" -ForegroundColor Green }
    else { $script:Fail++; Write-Host "  FAIL $Name" -ForegroundColor Red }
}
function Assert-Status($Result, [string]$Expected, [string]$Name) {
    Assert-True ($Result.Status -eq $Expected) "$Name -> $Expected (실제: $($Result.Status) / $($Result.Current))"
}

Write-Host '[구문]'
Assert-True ($errors.Count -eq 0) "PowerShell 구문 오류 없음 ($($errors.Count))"

# 2) 읽기 전용·외부 통신 금지 정적 검사
Write-Host '[읽기 전용 가드]'
$code = Get-Content -LiteralPath $scriptPath -Raw
$forbidden = @('Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Set-MpPreference', 'Set-NetFirewall', 'Set-LocalUser',
    'Enable-BitLocker', 'Disable-WindowsOptionalFeature', 'Set-SmbServerConfiguration', 'Invoke-WebRequest', 'Invoke-RestMethod',
    'Net.WebClient', 'Net.Http', 'Start-BitsTransfer', 'Send-MailMessage', 'reg.exe add', 'reg add', 'reg delete', '/configure', 'Stop-Service', 'Set-Service')
foreach ($f in $forbidden) { Assert-True (-not $code.Contains($f)) "금지 패턴 없음: $f" }
$bytes = [IO.File]::ReadAllBytes($scriptPath)
Assert-True ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) 'UTF-8 BOM 저장 (PowerShell 5.1 한글 깨짐 방지)'

# 3) 판정 로직 (모의 데이터)
. $scriptPath

$script:M = @{}
function Reset-Mock {
    $script:M = @{
        Now = [datetime]'2026-10-29 10:00'; Admin = $true; Reg = @{}; RegNames = @{}
        Os = [pscustomobject]@{ Caption = 'Microsoft Windows 11 Pro'; ProductName = 'Windows 10 Pro'; EditionID = 'Professional'; DisplayVersion = '25H2'; Build = 26200; UBR = 9818 }
        Hotfix = @([pscustomobject]@{ HotFixID = 'KB5127936'; Description = 'Security Update'; InstalledOn = [datetime]'2026-10-28' })
        Defender = [pscustomobject]@{ AntivirusEnabled = $true; AMRunningMode = 'Normal'; RealTimeProtectionEnabled = $true; AntivirusSignatureAge = 0; AntivirusSignatureVersion = '1.0.0.0'; AntivirusSignatureLastUpdated = [datetime]'2026-10-29 08:00' }
        Av = @('Windows Defender')
        Fw = @([pscustomobject]@{ Name = 'Domain'; Enabled = 'True' }, [pscustomobject]@{ Name = 'Private'; Enabled = 'True' }, [pscustomobject]@{ Name = 'Public'; Enabled = 'True' })
        Net = @('Force user logoff how long after time expires?:       Never', 'Minimum password age (days):                          1',
            'Maximum password age (days):                          90', 'Minimum password length:                              8',
            'Length of password history maintained:                5', 'Lockout threshold:                                    5',
            'Lockout duration (minutes):                           30', 'Lockout observation window (minutes):                 30',
            'Computer role:                                        WORKSTATION', 'The command completed successfully.')
        Sec = @{ PasswordComplexity = '1' }
        Admins = @([pscustomobject]@{ Name = 'PC1\Administrator'; ObjectClass = 'User'; Source = 'Local'; SID = 'S-1-5-21-1-2-3-500' })
        Users = @([pscustomobject]@{ Name = 'Administrator'; Enabled = $false; SID = 'S-1-5-21-1-2-3-500' }, [pscustomobject]@{ Name = 'Guest'; Enabled = $false; SID = 'S-1-5-21-1-2-3-501' }, [pscustomobject]@{ Name = 'kim'; Enabled = $true; SID = 'S-1-5-21-1-2-3-1001' })
        Me = 'PC1\kim'
        Shares = @([pscustomobject]@{ Name = 'ADMIN$'; Path = 'C:\Windows'; Type = 2147483648 }, [pscustomobject]@{ Name = 'C$'; Path = 'C:\'; Type = 2147483648 }, [pscustomobject]@{ Name = 'IPC$'; Path = ''; Type = 2147483651 })
        BitLocker = [pscustomobject]@{ ProtectionStatus = 'On'; VolumeStatus = 'FullyEncrypted'; EncryptionPercentage = 100 }
        Smb1 = [pscustomobject]@{ ServerEnabled = $false; ClientDriverStart = $null; FeatureState = 'Disabled' }
        Listen = @([pscustomobject]@{ Address = '0.0.0.0'; Port = 135; Process = 'svchost' }, [pscustomobject]@{ Address = '0.0.0.0'; Port = 445; Process = 'System' })
        Vol = @([pscustomobject]@{ DeviceID = 'C:'; FileSystem = 'NTFS' })
        Ip = @('192.168.10.23')
    }
    $r = $script:M.Reg
    $r['HKCU:\Control Panel\Desktop|ScreenSaveActive'] = '1'
    $r['HKCU:\Control Panel\Desktop|ScreenSaverIsSecure'] = '1'
    $r['HKCU:\Control Panel\Desktop|ScreenSaveTimeOut'] = '600'
    $r['HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoDriveTypeAutoRun'] = 255
    $r['HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}|Deny_Write'] = 1
    $r['HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server|fDenyTSConnections'] = 1
    $r['HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance|fAllowToGetHelp'] = 0
}
function Get-EckNow { $script:M.Now }
function Test-EckIsAdmin { $script:M.Admin }
function Get-EckReg([string]$Path, [string]$Name) { $script:M.Reg["$Path|$Name"] }
function Get-EckRegValueNames([string]$Path) { if ($script:M.RegNames.ContainsKey($Path)) { $script:M.RegNames[$Path] } else { @() } }
function Get-EckOsInfo { $script:M.Os }
function Get-EckHotfixes { $script:M.Hotfix }
function Get-EckDefender { $script:M.Defender }
function Get-EckAvProducts { $script:M.Av }
function Get-EckFirewallProfiles { $script:M.Fw }
function Get-EckNetAccounts { $script:M.Net }
function Get-EckSecPolicy { if ($script:M.Admin) { $script:M.Sec } else { $null } }
function Get-EckLocalAdmins { $script:M.Admins }
function Get-EckLocalUsers { $script:M.Users }
function Get-EckCurrentUser { $script:M.Me }
function Get-EckShares { $script:M.Shares }
function Get-EckBitLocker { if ($script:M.Admin) { $script:M.BitLocker } else { $null } }
function Get-EckSmb1 { $script:M.Smb1 }
function Get-EckListeners { $script:M.Listen }
function Get-EckVolumes { $script:M.Vol }
function Get-EckIPv4 { $script:M.Ip }

Write-Host '[기본 양호 시나리오]'
Reset-Mock
$all = Invoke-EckChecks
Assert-True ($all.Count -eq 21) "점검 항목 21개 ($($all.Count))"
foreach ($r in $all) { Assert-Status $r '양호' "$($r.Id) $($r.Item)" }
$ids = @($all | ForEach-Object { $_.Id })
Assert-True ((@($ids | Select-Object -Unique)).Count -eq 21) '항목 ID 중복 없음'
$kisa = @($all | Where-Object { $_.Kisa } | ForEach-Object { $_.Kisa } | Sort-Object -Unique)
Assert-True (($kisa -join ',') -eq 'PC-01,PC-02,PC-04,PC-07,PC-10,PC-11,PC-12,PC-13,PC-14,PC-15,PC-16,PC-17,PC-18') "KISA 매핑 목록 ($($kisa -join ','))"

Write-Host '[OS 지원 기간]'
Reset-Mock; $script:M.Os.Build = 26100
Assert-Status (Test-EckOsSupport) '취약' 'Win11 24H2 Pro, 2026-10-29 (Home/Pro 지원 종료 2026-10-13)'
$script:M.Os.EditionID = 'Enterprise'
Assert-Status (Test-EckOsSupport) '양호' 'Win11 24H2 Enterprise (2027-10-12까지)'
$script:M.Os.EditionID = 'EnterpriseS'
Assert-Status (Test-EckOsSupport) '양호' 'Win11 LTSC 2024 (2029-10-09까지)'
Reset-Mock; $script:M.Os.Build = 19045
Assert-Status (Test-EckOsSupport) '취약' 'Windows 10 22H2 Pro (2025-10-14 종료)'
Reset-Mock; $script:M.Os.Build = 29999
Assert-Status (Test-EckOsSupport) '확인필요' '지원표에 없는 빌드'

Write-Host '[패치·백신]'
Reset-Mock; $script:M.Hotfix[0].InstalledOn = [datetime]'2026-09-10'
Assert-Status (Test-EckPatchAge) '확인필요' '49일 경과'
$script:M.Hotfix[0].InstalledOn = [datetime]'2026-07-01'
Assert-Status (Test-EckPatchAge) '취약' '120일 경과'
$script:M.Hotfix = @()
Assert-Status (Test-EckPatchAge) '확인필요' '설치 기록 없음'
Reset-Mock; $script:M.Defender.AntivirusSignatureAge = 3
Assert-Status (Test-EckAntivirus) '확인필요' '시그니처 3일'
$script:M.Defender.AntivirusSignatureAge = 14
Assert-Status (Test-EckAntivirus) '취약' '시그니처 14일'
Reset-Mock; $script:M.Defender.AMRunningMode = 'Passive Mode'; $script:M.Av = @('Windows Defender', 'V3 Lite')
Assert-Status (Test-EckAntivirus) '확인필요' '타사 백신 + Defender 수동 모드'
Assert-Status (Test-EckRealtime) '확인필요' '타사 백신 실시간 감시'
Reset-Mock; $script:M.Defender = $null; $script:M.Av = @()
Assert-Status (Test-EckAntivirus) '취약' '백신 없음'
Reset-Mock; $script:M.Defender.RealTimeProtectionEnabled = $false
Assert-Status (Test-EckRealtime) '취약' '실시간 보호 꺼짐'

Write-Host '[방화벽·화면잠금]'
Reset-Mock; $script:M.Fw[2].Enabled = 'False'
Assert-Status (Test-EckFirewall) '취약' '공용 프로필 꺼짐'
Reset-Mock; $script:M.Reg['HKCU:\Control Panel\Desktop|ScreenSaveTimeOut'] = '900'
Assert-Status (Test-EckScreenLock) '취약' '대기 15분'
$script:M.Reg['HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|InactivityTimeoutSecs'] = 300
Assert-Status (Test-EckScreenLock) '양호' '비활성 한도 300초 정책'
Reset-Mock; $script:M.Reg['HKCU:\Control Panel\Desktop|ScreenSaverIsSecure'] = '0'
Assert-Status (Test-EckScreenLock) '취약' '암호 보호 없음'

Write-Host '[암호·계정]'
Reset-Mock; $script:M.Net[2] = 'Maximum password age (days):                          Unlimited'
Assert-Status (Test-EckPasswordMaxAge -Policy (Get-EckPasswordPolicy)) '취약' '최대 사용 기간 무제한'
Reset-Mock; $script:M.Net = @('강제 로그오프 시간 이후 사용자 강제 로그오프?:  안 함', '최소 암호 사용 기간(일):  0', '최대 암호 사용 기간(일):  42', '최소 암호 길이:  0', '암호 기록 개수:  없음', '잠금 임계값:  안 함', '잠금 기간(분):  10', '잠금 관찰 창(분):  10', '컴퓨터 역할:  WORKSTATION', '명령을 잘 실행했습니다.')
$p = Get-EckPasswordPolicy
Assert-Status (Test-EckPasswordMaxAge -Policy $p) '양호' '한국어 출력 42일'
Assert-Status (Test-EckPasswordPolicy -Policy $p) '취약' '한국어 출력 최소 길이 0'
Assert-Status (Test-EckLockout -Policy $p) '취약' '한국어 출력 잠금 안 함'
Reset-Mock; $script:M.Admin = $false
Assert-Status (Test-EckPasswordPolicy -Policy (Get-EckPasswordPolicy)) '확인필요' '비관리자: 복잡성 확인 불가'
Reset-Mock; $script:M.Sec = @{ PasswordComplexity = '0' }
Assert-Status (Test-EckPasswordPolicy -Policy (Get-EckPasswordPolicy)) '취약' '복잡성 사용 안 함'
Reset-Mock; $script:M.Reg['HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon|AutoAdminLogon'] = '1'
Assert-Status (Test-EckAutoLogon) '취약' 'AutoAdminLogon=1'
Reset-Mock; $script:M.RegNames['HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'] = @('Shell', 'DefaultPassword')
Assert-Status (Test-EckAutoLogon) '취약' 'DefaultPassword 저장'
Reset-Mock; $script:M.Users[1].Enabled = $true
Assert-Status (Test-EckGuest) '취약' 'Guest 사용'
Reset-Mock; $script:M.Admins += [pscustomobject]@{ Name = 'PC1\kim'; ObjectClass = 'User'; Source = 'Local'; SID = 'S-1-5-21-1-2-3-1001' }
Assert-Status (Test-EckLocalAdmins) '확인필요' '현재 사용자가 관리자'

Write-Host '[공유·매체·암호화]'
Reset-Mock; $script:M.Shares += [pscustomobject]@{ Name = '자료실'; Path = 'D:\share'; Type = 0 }
Assert-Status (Test-EckShares) '취약' '사용자 공유 폴더'
Reset-Mock; $script:M.Shares += [pscustomobject]@{ Name = 'backup$'; Path = 'D:\bk'; Type = 0 }
Assert-Status (Test-EckShares) '확인필요' '숨김 사용자 공유'
Reset-Mock; $script:M.Reg.Remove('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoDriveTypeAutoRun')
Assert-Status (Test-EckAutorun) '취약' '자동 실행 정책 없음'
$script:M.Reg['HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoDriveTypeAutoRun'] = 145
Assert-Status (Test-EckAutorun) '취약' 'NoDriveTypeAutoRun=0x91(일부 드라이브)'
Reset-Mock; $script:M.Reg.Remove('HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}|Deny_Write')
Assert-Status (Test-EckUsbStorage) '확인필요' 'USB 통제 정책 없음'
$script:M.Reg['HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR|Start'] = 4
Assert-Status (Test-EckUsbStorage) '양호' 'USBSTOR Start=4'
Reset-Mock; $script:M.BitLocker.ProtectionStatus = 'Off'
Assert-Status (Test-EckBitLocker) '취약' 'BitLocker 꺼짐'
Reset-Mock; $script:M.Admin = $false
Assert-Status (Test-EckBitLocker) '확인필요' '비관리자'

Write-Host '[원격·네트워크]'
Reset-Mock; $script:M.Reg['HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server|fDenyTSConnections'] = 0
$script:M.Reg['HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp|UserAuthentication'] = 1
Assert-Status (Test-EckRdp) '확인필요' 'RDP 켜짐 + NLA'
$script:M.Reg['HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp|UserAuthentication'] = 0
Assert-Status (Test-EckRdp) '취약' 'RDP 켜짐, NLA 없음'
$script:M.Reg['HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services|fDenyTSConnections'] = 1
Assert-Status (Test-EckRdp) '양호' '정책이 로컬 설정보다 우선'
Reset-Mock; $script:M.Reg['HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance|fAllowToGetHelp'] = 1
Assert-Status (Test-EckRemoteAssistance) '취약' '원격 지원 허용'
Reset-Mock; $script:M.Smb1 = [pscustomobject]@{ ServerEnabled = $false; ClientDriverStart = 2; FeatureState = $null }
Assert-Status (Test-EckSmb1) '취약' 'SMBv1 클라이언트 드라이버 사용'
$script:M.Smb1 = [pscustomobject]@{ ServerEnabled = $null; ClientDriverStart = $null; FeatureState = $null }
Assert-Status (Test-EckSmb1) '확인필요' 'SMB 서버 상태 미확인'
Reset-Mock; $script:M.Listen += [pscustomobject]@{ Address = '0.0.0.0'; Port = 3389; Process = 'svchost' }
Assert-Status (Test-EckListeningPorts) '확인필요' '3389 대기'
$script:M.Listen += [pscustomobject]@{ Address = '::'; Port = 23; Process = 'tlntsvr' }
Assert-Status (Test-EckListeningPorts) '취약' '23(Telnet) 대기'
Reset-Mock; $script:M.Listen = @([pscustomobject]@{ Address = '127.0.0.1'; Port = 3306; Process = 'mysqld' })
Assert-Status (Test-EckListeningPorts) '양호' '루프백 3306은 제외'
Reset-Mock; $script:M.Vol += [pscustomobject]@{ DeviceID = 'D:'; FileSystem = 'FAT32' }
Assert-Status (Test-EckNtfs) '취약' 'FAT32 고정 디스크'

Write-Host '[예외 처리·마스킹·보고서]'
Reset-Mock
function Get-EckShares { throw '접근 거부' }
$all = Invoke-EckChecks
$err = @($all | Where-Object { $_.Current -like '*접근 거부*' }); Assert-True ($all.Count -eq 21 -and $err.Count -eq 1 -and $err[0].Id -eq 'EP-13' -and $err[0].Status -eq '확인필요') '수집 오류는 확인필요로 기록하고 나머지 계속'
function Get-EckShares { $script:M.Shares }
$masked = Protect-EckText 'PC1\kim 192.168.10.23 Administrator' @('PC1', 'kim', 'PC1\kim', '192.168.10.23')
Assert-True ($masked -eq '*** x.x.x.x Administrator') "마스킹 결과: $masked"
Reset-Mock
$html = New-EckHtmlReport -Results (Invoke-EckChecks) -Meta @{ '점검 시각' = '2026-10-29 10:00:00'; '컴퓨터 이름' = '<b>x</b>' }
Assert-True ($html.Contains('엔드포인트 보안 점검 보고서') -and $html.Contains('&lt;b&gt;x&lt;/b&gt;') -and -not $html.Contains('<b>x</b>')) 'HTML 보고서 생성, 값 이스케이프'
Assert-True (-not ($html -match 'https?://')) 'HTML 보고서에 외부 리소스 없음'

Write-Host ''
Write-Host ("결과: 통과 {0} / 실패 {1}" -f $script:Pass, $script:Fail)
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }

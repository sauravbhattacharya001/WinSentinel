#Requires -RunAsAdministrator
# Fix network security findings from WinSentinel audit

Write-Host "=== WinSentinel Network Fixes ===" -ForegroundColor Cyan

# 1. Disable LLMNR (credential poisoning risk)
Write-Host "`n[1/3] Disabling LLMNR..." -ForegroundColor Yellow
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
Write-Host "  LLMNR disabled" -ForegroundColor Green

# 2. Enable SMB signing requirement (MITM prevention)
Write-Host "`n[2/3] Enabling SMB signing..." -ForegroundColor Yellow
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Write-Host "  SMB signing required" -ForegroundColor Green

# 3. Disable NetBIOS over TCP/IP on all adapters (poisoning risk)
Write-Host "`n[3/3] Disabling NetBIOS over TCP/IP..." -ForegroundColor Yellow
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($adapter in $adapters) {
    $result = $adapter.SetTcpipNetbios(2)
    $status = if ($result.ReturnValue -eq 0) { "OK" } else { "code $($result.ReturnValue)" }
    Write-Host "  $($adapter.Description): $status" -ForegroundColor Green
}

Write-Host "`n=== All fixes applied ===" -ForegroundColor Cyan
Write-Host "Re-run WinSentinel audit to verify improvements." -ForegroundColor Gray

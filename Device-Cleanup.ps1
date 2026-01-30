# Enable scripts
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force

# 1. Check for Administrator Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires Administrator privileges. Please run PowerShell as Administrator."
    Start-Sleep -Seconds 3
    Exit
}

# 2. Setup Logging
$LogDir = "C:\Data\Maintenance-Logs"

# Create directory if it doesn't exist
if (!(Test-Path -Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$DateString = Get-Date -Format "yyyyMMdd-HHmm"
$LogFile = "$LogDir\Maintenance_$DateString.txt"

# Start recording all output to the text file
Start-Transcript -Path $LogFile -Append

Write-Host "--- Starting System Maintenance: $(Get-Date) ---" -ForegroundColor Cyan

# 3. Clear Temporary Files
Write-Host "`n[1/4] Clearing Temporary Files..." -ForegroundColor Yellow

function Remove-FilesWithoutLock ($Path) {
    if (Test-Path $Path) {
        Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Remove-Item $_.FullName -Force -Recurse -ErrorAction Stop
                Write-Output "Deleted: $($_.FullName)"
            } 
            catch {
                # File is likely in use; skip it
            }
        }
    }
}

Remove-FilesWithoutLock -Path $env:TEMP
Remove-FilesWithoutLock -Path "C:\Windows\Temp"
Remove-FilesWithoutLock -Path "C:\Windows\Prefetch"

Write-Host "Temporary files cleanup complete." -ForegroundColor Green

# 4. Disk Cleanup
Write-Host "`n[2/4] Running Disk Cleanup..." -ForegroundColor Yellow

$StateFlagsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"

function Set-CleanupFlag ($KeyName) {
    $FullKey = "$StateFlagsPath\$KeyName"
    if (Test-Path $FullKey) {
        Set-ItemProperty -Path $FullKey -Name "StateFlags0001" -Value 2 -Type DWord -ErrorAction SilentlyContinue
    }
}

$CleanupTargets = @("Temporary Files", "Recycle Bin", "Temporary Setup Files", "Old Chkdsk Files", "Previous Installations", "Windows Upgrade Log Files")

foreach ($target in $CleanupTargets) {
    Set-CleanupFlag -KeyName $target
}

Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -WindowStyle Hidden -Wait
Write-Host "Disk Cleanup initiated and finished." -ForegroundColor Green

# 5. Optimize Drive
Write-Host "`n[3/4] Optimizing C: Drive..." -ForegroundColor Yellow

# Check for Storage module
if (Get-Module -ListAvailable -Name "Storage") {
    if (!(Get-Module -Name "Storage")) {
        Import-Module Storage
    }
    
    try {
        Optimize-Volume -DriveLetter C -Verbose
        Write-Host "Drive optimization complete." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to execute Optimize-Volume. $_"
    }
}
else {
    Write-Warning "The 'Storage' module is not available on this system. Skipping optimization."
}

# 6. Windows Updates
Write-Host "`n[4/4] Triggering Windows Updates..." -ForegroundColor Yellow

# Check for Windows Update module
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Host "PSWindowsUpdate module not found. Installing now..." -ForegroundColor Cyan
    # Trust the NuGet and PSGallery to prevent untrusted prompt
    Get-PSRepository -Name 'NuGet' | Set-PSRepository -InstallationPolicy Trusted
    Get-PSRepository -Name 'PSGallery' | Set-PSRepository -InstallationPolicy Trusted
    # Install the NuGet provider
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    # Install the module from the PSGallery
    Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope CurrentUser
}
else {
    Write-Host "PSWindowsUpdate module is already installed." -ForegroundColor Green
}

Import-Module -Name PSWindowsUpdate
Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d

try {
    Get-WUInstall -MicrosoftUpdate -Category "Security Updates" -AcceptAll

    Get-WUInstall -MicrosoftUpdate -Category "Critical Updates" -AcceptAll

    Write-Host "Windows Update scan and install triggered successfully." -ForegroundColor Green
}
catch {
    Write-Error "Failed to trigger Windows Update client."
}

Write-Host "`n--- Maintenance Complete: $(Get-Date) ---" -ForegroundColor Cyan

# Stop recording
Stop-Transcript


# AI-Powered System Diagnostics with LINE Notification
# ระบบวิเคราะห์ปัญหาด้วย AI และส่งรีพอร์ตไปยัง LINE อัตโนมัติ

# === Parameters and Configurations ===
param(
    [switch]$AutoFix,
    [switch]$DetailedReport,
    [switch]$UpdateScript,
    [string]$GeminiApiKey = $env:GEMINI_API_KEY
)

# Configuration
# โปรดทราบ: การเก็บ token และ user ID แบบ hard-coded ไม่ปลอดภัยใน Production Environment
# ควรใช้ Environment Variables หรือ Secure Vault แทน
$LINE_BOT_TOKEN = "0LsboIwNlj+qpW2FNpIIUnDJtUFN8vRtnOR8yAcDkRUstEflXFLetePEQGspYJSNPw/fYGz7VYQJ0zKRjbA4Zra1toUsFPyuJ7aRWDRlddQVfHYSGV33XwWQek43ZdR5gXUqE35NGGyvnGa+12ihdAdB04t89/1O/w1cDnyilFU="
$LINE_USER_ID = "Uf7dc70114f8b83ce8346b8bad3566c0a"
$LINE_API_URL = "https://api.line.me/v2/bot/message/push"
$GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key=$GeminiApiKey"
$SCRIPT_UPDATE_URL = "https://raw.githubusercontent.com/your-username/your-repo/main/SystemDiagnostics.ps1" # เปลี่ยน URL นี้ไปยังที่เก็บสคริปต์เวอร์ชันล่าสุดของคุณ

# Global variables
$Script:DiagnosticResults = [System.Collections.ArrayList]::new()
$Script:FixedIssues = [System.Collections.ArrayList]::new()
$Script:FailedFixes = [System.Collections.ArrayList]::new()
$Script:RebootRequired = $false

# === Helper Functions ===

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Write-Host $logMessage
    try {
        Add-Content -Path "SystemDiagnostics.log" -Value $logMessage -Encoding UTF8
    } catch {
        Write-Host "WARNING: Failed to write to log file. $($_.Exception.Message)"
    }
}

function Send-LineMessage {
    param([string]$Message)
    
    if (-not $LINE_BOT_TOKEN) {
        Write-Log "LINE BOT TOKEN is not set. Cannot send notification." "ERROR"
        return $false
    }
    
    try {
        $headers = @{
            "Authorization" = "Bearer $LINE_BOT_TOKEN"
            "Content-Type" = "application/json"
        }
        
        $body = @{
            to = $LINE_USER_ID
            messages = @(
                @{
                    type = "text"
                    text = $Message
                }
            )
        }
        
        # Convert the body to JSON string, then to UTF8 byte array for correct encoding
        $jsonBody = $body | ConvertTo-Json -Depth 3
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($jsonBody)
        
        $response = Invoke-RestMethod -Uri $LINE_API_URL -Method POST -Headers $headers -Body $bytes
        Write-Log "LINE message sent successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to send LINE message: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-AIAnalysis {
    param([string]$SystemData)
    
    if (-not $GeminiApiKey) {
        Write-Log "Gemini API key not provided. Using basic analysis." "WARNING"
        return "การวิเคราะห์ระบบเบื้องต้นเสร็จสิ้น สำหรับการวิเคราะห์ด้วย AI กรุณาใส่ Gemini API key."
    }
    
    try {
        $headers = @{
            "Content-Type" = "application/json"
        }
        
        $prompt = @"
คุณเป็น System Administrator ผู้เชี่ยวชาญ วิเคราะห์ข้อมูลระบบต่อไปนี้และให้คำแนะนำ:

$SystemData

กรุณาวิเคราะห์และตอบในรูปแบบ:
1. ปัญหาที่พบ (ถ้ามี)
2. ระดับความรุนแรง (สูง/กลาง/ต่ำ)
3. วิธีแก้ไขที่แนะนำ
4. คำสั่ง PowerShell ที่ใช้แก้ไข (ถ้าเป็นไปได้)

ตอบเป็นภาษาไทยและให้ข้อมูลที่เข้าใจง่าย
"@
        
        $body = @{
            contents = @(
                @{
                    role = "user"
                    parts = @(
                        @{ text = $prompt }
                    )
                }
            )
            generationConfig = @{
                temperature = 0.3
                maxOutputTokens = 1000
            }
        } | ConvertTo-Json -Depth 4
        
        $response = Invoke-RestMethod -Uri $GEMINI_API_URL -Method POST -Headers $headers -Body $body
        return $response.candidates[0].content.parts[0].text
    }
    catch {
        Write-Log "AI Analysis failed: $($_.Exception.Message)" "ERROR"
        return "ไม่สามารถเชื่อมต่อ AI สำหรับการวิเคราะห์ได้ กรุณาตรวจสอบ API Key"
    }
}

function Update-Script {
    Write-Log "Checking for script updates..." "INFO"
    try {
        $latestScript = Invoke-RestMethod -Uri $SCRIPT_UPDATE_URL
        if ($latestScript -and $latestScript -ne (Get-Content -Path $PSScriptRoot\$PSScriptRoot.ps1 -Raw)) {
            Write-Log "New version found. Updating script..." "INFO"
            $latestScript | Out-File -FilePath $PSScriptRoot\$PSScriptRoot.ps1 -Encoding UTF8
            Send-LineMessage "✅ สคริปต์ได้รับการอัปเดตแล้ว กรุณารันสคริปต์อีกครั้ง"
            exit
        } else {
            Write-Log "Script is already up-to-date." "INFO"
            Send-LineMessage "✅ สคริปต์เป็นเวอร์ชันล่าสุดแล้ว"
        }
    }
    catch {
        Write-Log "Failed to check for updates: $($_.Exception.Message)" "ERROR"
        Send-LineMessage "❌ ไม่สามารถอัปเดตสคริปต์ได้: $($_.Exception.Message)"
    }
}

# === Diagnostic Functions ===

function Get-SystemInfo {
    Write-Log "Collecting system information..." "INFO"
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $systemInfo = @{
            OSName = $osInfo.Caption
            OSBuild = $osInfo.BuildNumber
            LastBootUpTime = $osInfo.LastBootUpTime
            Uptime = (New-TimeSpan -Start $osInfo.LastBootUpTime -End (Get-Date)).ToString()
            ComputerName = $env:COMPUTERNAME
        }
        $Script:DiagnosticResults.Add("✅ System Information Collected")
        return $systemInfo
    }
    catch {
        $Script:DiagnosticResults.Add("❌ System Information Collection Failed: $($_.Exception.Message)")
        Write-Log "System info collection failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-SystemPerformance {
    Write-Log "Checking system performance..." "INFO"
    
    $performance = @{}
    
    try {
        # CPU Usage
        $cpu = Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average
        $performance.CPU = [math]::Round($cpu.Average, 2)
        
        # Memory Usage
        $memory = Get-CimInstance -ClassName Win32_OperatingSystem
        $totalMemory = [math]::Round($memory.TotalVisibleMemorySize / 1MB, 2)
        $freeMemory = [math]::Round($memory.FreePhysicalMemory / 1MB, 2)
        $usedMemory = $totalMemory - $freeMemory
        $performance.MemoryUsedPercent = [math]::Round(($usedMemory / $totalMemory) * 100, 2)
        $performance.MemoryUsedGB = $usedMemory
        $performance.MemoryTotalGB = $totalMemory
        
        # Disk Usage
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        $performance.Disks = @()
        foreach ($disk in $disks) {
            $totalSize = [math]::Round($disk.Size / 1GB, 2)
            $freeSpace = [math]::Round($disk.FreeSpace / 1GB, 2)
            if ($totalSize -gt 0) {
                $usedPercent = [math]::Round((($totalSize - $freeSpace) / $totalSize) * 100, 2)
            } else {
                $usedPercent = 0
            }
            
            $performance.Disks += @{
                Drive = $disk.DeviceID
                TotalGB = $totalSize
                FreeGB = $freeSpace
                UsedPercent = $usedPercent
            }
        }
        
        $Script:DiagnosticResults.Add("✅ System Performance Check Completed")
        return $performance
    }
    catch {
        $Script:DiagnosticResults.Add("❌ System Performance Check Failed: $($_.Exception.Message)")
        Write-Log "Performance check failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-SystemErrors {
    Write-Log "Checking system errors..." "INFO"
    
    try {
        # Check Windows Event Log for critical and error messages (last 24 hours)
        $yesterday = (Get-Date).AddDays(-1)
        # Modified to get all errors and critical events in one go
        $eventQuery = @{
            LogName = 'System'
            Level = 1, 2
            StartTime = $yesterday
        }
        
        $events = Get-WinEvent -FilterHashtable $eventQuery -ErrorAction SilentlyContinue | Select-Object -First 20
        
        $errorSummary = @{
            Errors = @()
        }
        
        if ($events) {
            foreach ($event in $events) {
                $errorSummary.Errors += @{
                    Time = $event.TimeCreated
                    ID = $event.Id
                    Source = $event.ProviderName
                    Level = $event.LevelDisplayName
                    Message = $event.Message.Substring(0, [Math]::Min(150, $event.Message.Length)) # Limit message length
                }
            }
        }
        
        $Script:DiagnosticResults.Add("✅ System Error Check Completed")
        return $errorSummary
    }
    catch {
        $Script:DiagnosticResults.Add("❌ System Error Check Failed: $($_.Exception.Message)")
        Write-Log "Error check failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-ServiceStatus {
    Write-Log "Checking all services..." "INFO"
    
    try {
        # Check all services and filter for stopped ones that are not disabled
        $stoppedServices = Get-Service | Where-Object { $_.Status -eq 'Stopped' -and $_.StartType -ne 'Disabled' }
        
        $serviceStatus = @()
        foreach ($service in $stoppedServices) {
            $serviceStatus += @{
                Name = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status
                StartType = $service.StartType
            }
        }
        
        $Script:DiagnosticResults.Add("✅ Service Status Check Completed")
        return $serviceStatus
    }
    catch {
        $Script:DiagnosticResults.Add("❌ Service Status Check Failed: $($_.Exception.Message)")
        Write-Log "Service check failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-VirusScanStatus {
    Write-Log "Checking Windows Defender status..." "INFO"
    
    try {
        # Get Windows Defender status using the built-in cmdlet
        $mpStatus = Get-MpComputerStatus
        $lastScan = if ($mpStatus.LastFullScanEndTime -ne $null) { $mpStatus.LastFullScanEndTime } else { $mpStatus.LastQuickScanEndTime }
        
        $virusStatus = @{
            RealtimeProtection = if ($mpStatus.RealTimeProtectionEnabled) { "✅ เปิดใช้งาน" } else { "❌ ปิดใช้งาน" }
            AntivirusEnabled = if ($mpStatus.AntivirusEnabled) { "✅ เปิดใช้งาน" } else { "❌ ปิดใช้งาน" }
            AntispywareEnabled = if ($mpStatus.AntispywareEnabled) { "✅ เปิดใช้งาน" } else { "❌ ปิดใช้งาน" }
            LastScanTime = $lastScan
            LastScanAge = if ($lastScan -ne $null) { (New-TimeSpan -Start $lastScan).ToString() } else { "ไม่พบข้อมูล" }
        }
        
        $Script:DiagnosticResults.Add("✅ Virus Scan Status Check Completed")
        return $virusStatus
    }
    catch {
        $Script:DiagnosticResults.Add("❌ Virus Scan Status Check Failed: $($_.Exception.Message)")
        Write-Log "Virus scan status check failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-WindowsUpdateStatus {
    Write-Log "Checking for Windows Updates..." "INFO"
    
    try {
        $updateSession = New-Object -ComObject "Microsoft.Update.Session"
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResults = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        
        $updatesPending = $searchResults.Updates.Count
        
        $updateInfo = @{
            UpdatesPending = $updatesPending
            UpdatesAvailable = if ($updatesPending -gt 0) { "มีอัปเดตที่รอการติดตั้ง" } else { "ระบบเป็นเวอร์ชันล่าสุดแล้ว" }
        }
        
        $Script:DiagnosticResults.Add("✅ Windows Update Status Check Completed")
        return $updateInfo
    }
    catch {
        $Script:DiagnosticResults.Add("❌ Windows Update Status Check Failed: $($_.Exception.Exception.Message)")
        Write-Log "Windows Update check failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-HardwareStatus {
    Write-Log "Checking hardware status..." "INFO"
    
    try {
        $hardwareStatus = @()
        
        # Check Disk Health (SMART Status)
        $physicalDisks = Get-CimInstance -ClassName MSFT_PhysicalDisk -Namespace root\Microsoft\Windows\Storage -ErrorAction SilentlyContinue
        if ($physicalDisks) {
            foreach ($disk in $physicalDisks) {
                $status = if ($disk.HealthStatus -eq 1) { "✅ ปกติ" } else { "⚠️ มีปัญหา" }
                $hardwareStatus += @{
                    Type = "Disk ($($disk.FriendlyName))"
                    Status = $status
                    HealthStatus = $disk.HealthStatus
                }
            }
        } else {
            $hardwareStatus += @{
                Type = "Disk"
                Status = "ไม่สามารถตรวจสอบได้ (อาจต้องใช้สิทธิ์ Administrator)"
            }
        }
        
        $Script:DiagnosticResults.Add("✅ Hardware Status Check Completed")
        return $hardwareStatus
    }
    catch {
        $Script:DiagnosticResults.Add("❌ Hardware Status Check Failed: $($_.Exception.Message)")
        Write-Log "Hardware status check failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-GPUStatus {
    Write-Log "Checking GPU status..." "INFO"
    
    try {
        $gpuInfo = Get-CimInstance -ClassName Win32_VideoController
        $gpuStatus = @()
        
        foreach ($gpu in $gpuInfo) {
            $status = if ($gpu.Status -eq "OK") { "✅ ปกติ" } else { "⚠️ มีปัญหา" }
            $gpuStatus += @{
                Name = $gpu.Name
                AdapterRAM = [math]::Round($gpu.AdapterRAM / 1GB, 2)
                DriverVersion = $gpu.DriverVersion
                Status = $status
            }
        }
        
        $Script:DiagnosticResults.Add("✅ GPU Status Check Completed")
        return $gpuStatus
    }
    catch {
        $Script:DiagnosticResults.Add("❌ GPU Status Check Failed: $($_.Exception.Message)")
        Write-Log "GPU status check failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-MotherboardStatus {
    Write-Log "Checking Motherboard status..." "INFO"
    
    try {
        $mbInfo = Get-CimInstance -ClassName Win32_BaseBoard
        $mbStatus = @()
        
        foreach ($mb in $mbInfo) {
            $mbStatus += @{
                Manufacturer = $mb.Manufacturer
                Product = $mb.Product
                SerialNumber = $mb.SerialNumber
            }
        }
        
        $Script:DiagnosticResults.Add("✅ Motherboard Status Check Completed")
        return $mbStatus
    }
    catch {
        $Script:DiagnosticResults.Add("❌ Motherboard Status Check Failed: $($_.Exception.Message)")
        Write-Log "Motherboard status check failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-PowerSupplyStatus {
    Write-Log "Checking for unexpected power events (Power Supply stability)..." "INFO"
    
    try {
        # Check for unexpected shutdown events in the last 7 days (Event ID 41)
        $lastSevenDays = (Get-Date).AddDays(-7)
        $powerEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ProviderName = 'Microsoft-Windows-Kernel-Power'
            ID = 41
            StartTime = $lastSevenDays
        } -ErrorAction SilentlyContinue
        
        $psuStatus = @{
            UnexpectedShutdownCount = $powerEvents.Count
        }
        
        $Script:DiagnosticResults.Add("✅ Power Supply Stability Check Completed")
        return $psuStatus
    }
    catch {
        $Script:DiagnosticResults.Add("❌ Power Supply Stability Check Failed: $($_.Exception.Message)")
        Write-Log "Power Supply check failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Test-NetworkConnectivity {
    Write-Log "Testing network connectivity..." "INFO"
    
    try {
        $networkTests = @()
        $testSites = @('8.8.8.8', 'google.com', 'microsoft.com')
        
        foreach ($site in $testSites) {
            $result = Test-Connection -ComputerName $site -Count 2 -Quiet -ErrorAction SilentlyContinue
            $networkTests += @{
                Target = $site
                Status = if ($result) { "✅ Connected" } else { "❌ Failed" }
            }
        }
        
        $Script:DiagnosticResults.Add("✅ Network Connectivity Check Completed")
        return $networkTests
    }
    catch {
        $Script:DiagnosticResults.Add("❌ Network Connectivity Check Failed: $($_.Exception.Message)")
        Write-Log "Network test failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# === Remediation Functions ===

function Invoke-WindowsUpdate {
    Write-Log "Starting Windows Update check and installation..." "INFO"
    
    try {
        # Check if PSWindowsUpdate module is installed
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Log "PSWindowsUpdate module not found. Installing..." "INFO"
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
            Write-Log "PSWindowsUpdate module installed successfully." "SUCCESS"
        }
        
        # Get pending updates
        $updatesToInstall = Get-WUList -ErrorAction Stop | Where-Object { $_.IsInstalled -eq $false -and $_.Title -notlike "*preview*" }
        
        if ($updatesToInstall.Count -gt 0) {
            Write-Log "Found $($updatesToInstall.Count) pending Windows updates. Starting installation..." "INFO"
            
            # Download and install updates silently
            $installResult = Install-WUFile -AcceptAll -AutoReboot -ErrorAction Stop
            
            # Check for reboot requirement
            if ($installResult.RebootRequired) {
                $Script:RebootRequired = $true
                $Script:FixedIssues.Add("🔄 Windows updates installed. ต้องรีบูตเครื่องเพื่อเสร็จสิ้นกระบวนการ")
            } else {
                $Script:FixedIssues.Add("✅ Windows updates installed successfully.")
            }
        } else {
            $Script:FixedIssues.Add("✅ Windows is already up-to-date. No updates to install.")
        }
    }
    catch {
        $Script:FailedFixes.Add("❌ Failed to install Windows Updates: $($_.Exception.Message)")
        Write-Log "Windows Update installation failed: $($_.Exception.Message)" "ERROR"
    }
}

function Invoke-AutoFix {
    Write-Log "Starting auto-fix procedures..." "INFO"
    
    # Auto-fix for common issues
    try {
        # Clear temporary files
        $tempPaths = @($env:TEMP, "C:\Windows\Temp", "C:\Windows\Prefetch")
        foreach ($path in $tempPaths) {
            if (Test-Path $path) {
                try {
                    Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction Stop
                    $Script:FixedIssues.Add("🧹 Cleaned temporary files in path: $path")
                }
                catch {
                    $Script:FailedFixes.Add("❌ Failed to clean temporary files in path: $path - $($_.Exception.Message)")
                }
            }
        }

        # Restart all stopped services
        $stoppedServices = Get-Service | Where-Object { $_.Status -eq 'Stopped' -and $_.StartType -ne 'Disabled' }
        if ($stoppedServices) {
            foreach ($service in $stoppedServices) {
                try {
                    Start-Service -Name $service.Name -ErrorAction Stop
                    $Script:FixedIssues.Add("🔧 Started service: $($service.DisplayName) ($($service.Name))")
                }
                catch {
                    $Script:FailedFixes.Add("❌ Failed to start service: $($service.DisplayName) ($($service.Name)) - $($_.Exception.Message)")
                }
            }
        } else {
            $Script:FixedIssues.Add("🔧 No stopped services to start.")
        }
        
        # Flush DNS
        try {
            ipconfig /flushdns | Out-Null
            $Script:FixedIssues.Add("🌐 DNS cache flushed")
        }
        catch {
            $Script:FailedFixes.Add("❌ Failed to flush DNS cache")
        }
        
        # Invoke Windows Update
        Invoke-WindowsUpdate
        
        Write-Log "Auto-fix procedures completed" "INFO"
    }
    catch {
        Write-Log "Auto-fix failed: $($_.Exception.Message)" "ERROR"
        $Script:FailedFixes.Add("❌ Auto-fix procedure failed: $($_.Exception.Message)")
    }
}

# === Report Generation ===

function Format-Report {
    param($SystemInfo, $Performance, $Errors, $Services, $Network, $Updates, $VirusStatus, $HardwareStatus, $GPUStatus, $MotherboardStatus, $PowerSupplyStatus, $AIAnalysis)
    
    $reportBuilder = [System.Text.StringBuilder]::new()
    [void]$reportBuilder.AppendLine("🖥️ **AI SYSTEM DIAGNOSTIC REPORT**")
    [void]$reportBuilder.AppendLine("📅 วันที่: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')")
    [void]$reportBuilder.AppendLine("💻 เครื่อง: $($SystemInfo.ComputerName)")
    [void]$reportBuilder.AppendLine("---")

    if ($Script:FailedFixes.Count -gt 0) {
        [void]$reportBuilder.AppendLine("❌ **ปัญหาที่แก้ไขไม่ได้ (ต้องตรวจสอบด้วยตนเอง):**")
        $Script:FailedFixes | ForEach-Object { [void]$reportBuilder.AppendLine("• $_") }
        [void]$reportBuilder.AppendLine("---")
    }
    
    $criticalStoppedServices = $Services | Where-Object { $_.StartType -eq 'Automatic' }
    if ($criticalStoppedServices.Count -gt 0) {
        [void]$reportBuilder.AppendLine("⚠️ **บริการสำคัญที่หยุดทำงาน:**")
        $criticalStoppedServices | ForEach-Object {
            [void]$reportBuilder.AppendLine("• $($_.DisplayName) ($($_.Name))")
        }
        [void]$reportBuilder.AppendLine("---")
    }

    if ($VirusStatus) {
        [void]$reportBuilder.AppendLine("🛡️ **สถานะการป้องกันไวรัส (Windows Defender):**")
        [void]$reportBuilder.AppendLine("• Real-time Protection: $($VirusStatus.RealtimeProtection)")
        [void]$reportBuilder.AppendLine("• Antivirus: $($VirusStatus.AntivirusEnabled)")
        [void]$reportBuilder.AppendLine("• Antispyware: $($VirusStatus.AntispywareEnabled)")
        [void]$reportBuilder.AppendLine("• สแกนครั้งล่าสุด: $($VirusStatus.LastScanTime)")
        [void]$reportBuilder.AppendLine("---")
    }
    
    [void]$reportBuilder.AppendLine("💾 **สถานะฮาร์ดแวร์:**")
    if ($HardwareStatus) {
        $HardwareStatus | ForEach-Object {
            [void]$reportBuilder.AppendLine("• $($_.Type): $($_.Status)")
        }
    }
    if ($GPUStatus) {
        $GPUStatus | ForEach-Object {
            [void]$reportBuilder.AppendLine("• GPU ($($_.Name)): $($_.Status)")
        }
    }
    if ($MotherboardStatus) {
        $MotherboardStatus | ForEach-Object {
            [void]$reportBuilder.AppendLine("• เมนบอร์ด: $($_.Manufacturer) $($_.Product)")
        }
    }
    if ($PowerSupplyStatus) {
        $powerSupplyText = "✅ ปกติ"
        if ($PowerSupplyStatus.UnexpectedShutdownCount -gt 0) {
            $powerSupplyText = "⚠️ พบการปิดเครื่องผิดปกติ $($PowerSupplyStatus.UnexpectedShutdownCount) ครั้งใน 7 วันล่าสุด"
        }
        [void]$reportBuilder.AppendLine("• Power Supply: $powerSupplyText")
    }
    [void]$reportBuilder.AppendLine("---")

    if ($Errors -and $Errors.Errors.Count -gt 0) {
        [void]$reportBuilder.AppendLine("⚠️ **ข้อผิดพลาดที่พบ (Event Log):**")
        [void]$reportBuilder.AppendLine("• จำนวนข้อผิดพลาด: $($Errors.Errors.Count) รายการ")
        $Errors.Errors | ForEach-Object {
            [void]$reportBuilder.AppendLine("  - [เวลา: $($_.Time) | ระดับ: $($_.Level)]")
            [void]$reportBuilder.AppendLine("    ข้อความ: $($_.Message)")
        }
        [void]$reportBuilder.AppendLine("---")
    }
    
    [void]$reportBuilder.AppendLine("📊 **สถานะระบบโดยรวม:**")
    [void]$reportBuilder.AppendLine("• OS: $($SystemInfo.OSName)")
    [void]$reportBuilder.AppendLine("• Uptime: $($SystemInfo.Uptime)")
    [void]$reportBuilder.AppendLine("• CPU: $($Performance.CPU)%")
    [void]$reportBuilder.AppendLine("• RAM: $($Performance.MemoryUsedPercent)% ($($Performance.MemoryUsedGB)GB/$($Performance.MemoryTotalGB)GB)")
    [void]$reportBuilder.AppendLine("---")
    
    if ($AIAnalysis -and $AIAnalysis -ne "การวิเคราะห์ระบบเบื้องต้นเสร็จสิ้น สำหรับการวิเคราะห์ด้วย AI กรุณาใส่ Gemini API key.") {
        [void]$reportBuilder.AppendLine("🤖 **การวิเคราะห์โดย AI:**")
        [void]$reportBuilder.AppendLine($AIAnalysis)
        [void]$reportBuilder.AppendLine("---")
    }

    [void]$reportBuilder.AppendLine("✅ **การตรวจสอบเสร็จสิ้น:**")
    $Script:DiagnosticResults | ForEach-Object { [void]$reportBuilder.AppendLine("• $_") }
    
    if ($Script:FixedIssues.Count -gt 0) {
        [void]$reportBuilder.AppendLine("---")
        [void]$reportBuilder.AppendLine("✅ **ปัญหาที่แก้ไขแล้วโดยอัตโนมัติ:**")
        $Script:FixedIssues | ForEach-Object { [void]$reportBuilder.AppendLine("• $_") }
    }

    if ($Script:RebootRequired) {
        [void]$reportBuilder.AppendLine("---")
        [void]$reportBuilder.AppendLine("🚨 **แจ้งเตือน:** ต้องรีบูตเครื่องเพื่อเสร็จสิ้นการติดตั้งอัปเดต Windows.")
    }

    [void]$reportBuilder.AppendLine("---")
    [void]$reportBuilder.AppendLine("🔄 รายงานถูกสร้างโดยอัตโนมัติ")

    return $reportBuilder.ToString()
}

# === Main Execution ===

function Start-SystemDiagnostics {
    Write-Log "=== Starting AI System Diagnostics ===" "INFO"
    
    # Check for script updates if requested
    if ($UpdateScript) {
        Update-Script
        return
    }
    
    # Send initial notification
    Send-LineMessage "🔄 Start checking the system with AI...`n📅 $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')"
    
    # Collect system data
    $systemInfo = Get-SystemInfo
    $performance = Get-SystemPerformance
    $errors = Get-SystemErrors  
    $services = Get-ServiceStatus
    $virusStatus = Get-VirusScanStatus
    $hardwareStatus = Get-HardwareStatus
    $gpuStatus = Get-GPUStatus
    $motherboardStatus = Get-MotherboardStatus
    $powerSupplyStatus = Get-PowerSupplyStatus
    $network = Test-NetworkConnectivity
    $updates = Get-WindowsUpdateStatus
    
    # Prepare data for AI analysis
    $systemData = @"
System Information:
OS: $($systemInfo.OSName)
Uptime: $($systemInfo.Uptime)
Windows Updates: $($updates.UpdatesAvailable)

System Performance:
CPU: $($performance.CPU)%
Memory: $($performance.MemoryUsedPercent)%
Disk Usage: $(($performance.Disks | ForEach-Object { "$($_.Drive) $($_.UsedPercent)%" }) -join ", ")

Hardware Status:
Disk Health: $(($hardwareStatus | ForEach-Object { "$($_.Type): $($_.Status)" }) -join ", ")
GPU Status: $(($gpuStatus | ForEach-Object { "$($_.Name) - $($_.Status)" }) -join ", ")
Motherboard: $(($motherboardStatus | ForEach-Object { "$($_.Manufacturer) $($_.Product)" }) -join ", ")
Power Supply Stability: $($powerSupplyStatus.UnexpectedShutdownCount) unexpected shutdowns in the last 7 days.

Critical Errors: $($errors.Errors.Count)
Antivirus Status:
  Realtime Protection: $($virusStatus.RealtimeProtection)
  Last Scan: $($virusStatus.LastScanTime)

Stopped Services (important): $(($services | Where-Object { $_.StartType -eq 'Automatic' } | ForEach-Object { $_.Name }) -join ", ")

Network Issues: $(($network | Where-Object { $_.Status -like "*Failed*" } | ForEach-Object { $_.Target }) -join ", ")
"@

    # Get AI analysis
    $aiAnalysis = Get-AIAnalysis -SystemData $systemData
    
    # Auto-fix if requested
    if ($AutoFix) {
        Invoke-AutoFix
    }
    
    # Generate and send report
    $report = Format-Report -SystemInfo $systemInfo -Performance $performance -Errors $errors -Services $services -Network $network -Updates $updates -VirusStatus $virusStatus -HardwareStatus $hardwareStatus -GPUStatus $gpuStatus -MotherboardStatus $motherboardStatus -PowerSupplyStatus $powerSupplyStatus -AIAnalysis $aiAnalysis
    
    # Split long messages for LINE (max 5000 characters)
    if ($report.Length -gt 4000) {
        $parts = @()
        $lines = $report -split "`n"
        $currentPart = ""
        
        foreach ($line in $lines) {
            if (($currentPart.Length + $line.Length) -gt 4000) {
                $parts += $currentPart
                $currentPart = $line + "`n"
            }
            else {
                $currentPart += $line + "`n"
            }
        }
        if ($currentPart) { $parts += $currentPart }
        
        for ($i = 0; $i -lt $parts.Count; $i++) {
            $header = if ($i -eq 0) { "" } else { "📄 รายงาน (ส่วนที่ $($i + 1))`n`n" }
            Send-LineMessage ($header + $parts[$i])
            Start-Sleep -Seconds 1
        }
    }
    else {
        Send-LineMessage $report
    }
    
    # Save detailed report to file if requested
    if ($DetailedReport) {
        $reportFileName = "SystemDiagnostic_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $fullPath = Join-Path -Path $PSScriptRoot -ChildPath $reportFileName
        
        $detailedReport = $report + "`n`n=== DETAILED DATA ===`n"
        $detailedReport += "Performance Data: $($performance | ConvertTo-Json -Depth 3)`n"
        $detailedReport += "Error Data: $($errors | ConvertTo-Json -Depth 3)`n"
        $detailedReport += "Service Data: $($services | ConvertTo-Json -Depth 3)`n"
        $detailedReport += "Hardware Data: $($hardwareStatus | ConvertTo-Json -Depth 3)`n"
        $detailedReport += "GPU Data: $($gpuStatus | ConvertTo-Json -Depth 3)`n"
        $detailedReport += "Motherboard Data: $($motherboardStatus | ConvertTo-Json -Depth 3)`n"
        $detailedReport += "Power Supply Data: $($powerSupplyStatus | ConvertTo-Json -Depth 3)`n"
        $detailedReport += "Network Data: $($network | ConvertTo-Json -Depth 3)`n"
        
        try {
            $detailedReport | Out-File -FilePath $fullPath -Encoding UTF8
            Write-Log "Detailed report saved to: $fullPath" "INFO"
        }
        catch {
            Write-Log "Failed to save detailed report: $($_.Exception.Message)" "ERROR"
        }
    }
    
    Write-Log "=== System Diagnostics Completed ===" "INFO"
}

# Execute the main function
Start-SystemDiagnostics

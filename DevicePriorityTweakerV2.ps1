param([switch]$verbose)

$globalInterval = 0x0
$globalHCSPARAMSOffset = 0x4
$globalRTSOFF = 0x18
$userDefinedData = @{"DEV_" = @{"INTERVAL" = 0x4E20}}
$rwePath = "C:\Program Files (x86)\RW-Everything\Rw.exe"

function Dec-To-Hex($decimal) {
    return "0x$($decimal.ToString('X2'))"
}

function Get-Value-From-Address($address) {
    $address = Dec-To-Hex -decimal ([uint64]$address)
    $stdout = & $rwePath /Min /NoLogo /Stdout /Command="R32 $($address)" | Out-String
    $splitString = $stdout -split " "
    return [uint64]$splitString[-1]
}

function Get-Device-Addresses {
    $data = @{}
    $resources = Get-WmiObject -Class Win32_PNPAllocatedResource -ComputerName LocalHost -Namespace root\CIMV2
    foreach ($resource in $resources) {
        $deviceId = $resource.Dependent.Split("=")[1].Replace('"', '').Replace("\\", "\")
        $physicalAddress = $resource.Antecedent.Split("=")[1].Replace('"', '')
        if (-not $data.ContainsKey($deviceId) -and $deviceId -and $physicalAddress) {
            $data[$deviceId] = [uint64]$physicalAddress
        }
    }
    return $data
}

function Is-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-ControllerIMOD($controller, $deviceMap) {
    $deviceId = $controller.DeviceID
    if (-not $deviceMap.Contains($deviceId)) { return $null }

    $capabilityAddress = $deviceMap[$deviceId]
    $desiredInterval = $globalInterval
    $hcsparamsOffset = $globalHCSPARAMSOffset
    $rtsoff = $globalRTSOFF

    foreach ($hwid in $userDefinedData.Keys) {
        if ($deviceId -match $hwid) {
            $userDefinedController = $userDefinedData[$hwid]
            if ($userDefinedController.ContainsKey("INTERVAL")) { $desiredInterval = $userDefinedController["INTERVAL"] }
            if ($userDefinedController.ContainsKey("HCSPARAPS_OFFSET")) { $hcsparamsOffset = $userDefinedController["HCSPARAPS_OFFSET"] }
            if ($userDefinedController.ContainsKey("RTSOFF")) { $rtsoff = $userDefinedController["RTSOFF"] }
        }
    }

    $HCSPARAMSValue = Get-Value-From-Address -address ($capabilityAddress + $hcsparamsOffset)
    $HCSPARAMSBitmask = [Convert]::ToString($HCSPARAMSValue, 2)
    $maxIntrs = [Convert]::ToInt32($HCSPARAMSBitmask.Substring($HCSPARAMSBitmask.Length - 16, 8), 2)
    $RTSOFFValue = Get-Value-From-Address -address ($capabilityAddress + $rtsoff)
    $runtimeAddress = $capabilityAddress + $RTSOFFValue

    $imodValues = @()
    for ($i = 0; $i -lt $maxIntrs; $i++) {
        $interrupterAddress = $runtimeAddress + 0x24 + (0x20 * $i)
        $value = Get-Value-From-Address -address $interrupterAddress
        $imodValues += ($value -band 0xFFFF)
    }
    return $imodValues
}

function Write-ControllerIMOD($controller, $deviceMap, $newInterval) {
    $deviceId = $controller.DeviceID
    if (-not $deviceMap.Contains($deviceId)) { return $false }

    $capabilityAddress = $deviceMap[$deviceId]
    $hcsparamsOffset = $globalHCSPARAMSOffset
    $rtsoff = $globalRTSOFF

    foreach ($hwid in $userDefinedData.Keys) {
        if ($deviceId -match $hwid) {
            $userDefinedController = $userDefinedData[$hwid]
            if ($userDefinedController.ContainsKey("HCSPARAPS_OFFSET")) { $hcsparamsOffset = $userDefinedController["HCSPARAPS_OFFSET"] }
            if ($userDefinedController.ContainsKey("RTSOFF")) { $rtsoff = $userDefinedController["RTSOFF"] }
        }
    }

    $HCSPARAMSValue = Get-Value-From-Address -address ($capabilityAddress + $hcsparamsOffset)
    $HCSPARAMSBitmask = [Convert]::ToString($HCSPARAMSValue, 2)
    $maxIntrs = [Convert]::ToInt32($HCSPARAMSBitmask.Substring($HCSPARAMSBitmask.Length - 16, 8), 2)
    $RTSOFFValue = Get-Value-From-Address -address ($capabilityAddress + $rtsoff)
    $runtimeAddress = $capabilityAddress + $RTSOFFValue

    for ($i = 0; $i -lt $maxIntrs; $i++) {
        $interrupterAddress = $runtimeAddress + 0x24 + (0x20 * $i)
        $hexAddress = Dec-To-Hex -decimal ([uint64]$interrupterAddress)
        & $rwePath /Min /NoLogo /Stdout /Command="W32 $($hexAddress) $($newInterval)" | Out-Null
    }
    return $true
}

$AutoOptimize = $false
if ($args -contains "-AutoOptimize") {
    $AutoOptimize = $true
}

$FixedByteLength = 8
Add-Type -AssemblyName System.Windows.Forms, System.Drawing

$unknownDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Unknown' }
if ($unknownDevices) {
    foreach ($device in $unknownDevices) {
        try {
            Start-Process "pnputil.exe" -ArgumentList "/remove-device", "`"$($device.InstanceId)`"" -Wait -WindowStyle Hidden -ErrorAction Stop
        } 
        catch {
            Write-Warning "Failed to remove unknown device $($device.InstanceId): $_"
        }
    }
}

function Get-DeviceIRQCounts {
    $allocations = Get-CimInstance -ClassName Win32_PnPAllocatedResource -ErrorAction SilentlyContinue
    $irqCounts = @{}

    foreach ($allocation in $allocations) {
        try {
            $device = Get-CimInstance -CimInstance $allocation.Dependent -ErrorAction Stop
            
            if ($device.Name -like "*ACPI*") { continue }

            $resource = Get-CimInstance -CimInstance $allocation.Antecedent -ErrorAction Stop

            if ($resource.CimClass.CimClassName -eq 'Win32_IRQResource') {
                $deviceId = $device.DeviceID
                $formattedId = Get-PNPId $deviceId  
                
                if (-not $irqCounts.ContainsKey($formattedId)) {
                    $irqCounts[$formattedId] = 0
                }
                $irqCounts[$formattedId]++
            }
        }
        catch {
            Write-Warning "Error processing allocation: $_"
        }
    }

    return $irqCounts
}

function Create-ReservedCpuSetsUI {
    param(
        [int]$topPos
    )

    $script:reservedCheckboxes = @()

    $reservedGroupBox = New-Object System.Windows.Forms.GroupBox
    $reservedGroupBox.Text = "ReservedCpuSets"
    $reservedGroupBox.Width = 426
    $reservedGroupBox.Height = 300      
    $reservedGroupBox.Left = 10
    $reservedGroupBox.Top = $topPos
    $reservedGroupBox.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $reservedGroupBox.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $reservedGroupBox.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $panel.Controls.Add($reservedGroupBox)

    $reservedPanel = New-Object System.Windows.Forms.Panel
    $reservedPanel.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $reservedPanel.BorderStyle = "FixedSingle"
    $reservedPanel.Width = 395
    $reservedPanel.Height = 208           
    $reservedPanel.Left = 10
    $reservedPanel.Top = 20
    $reservedPanel.AutoScroll = $true
    $reservedGroupBox.Controls.Add($reservedPanel)

    $logicalCount = [Environment]::ProcessorCount
    $maxCoresPerColumn = 8
    $columns = [Math]::Ceiling($logicalCount / $maxCoresPerColumn)
    $columnWidth = 100
    $rowHeight = 25

    function script:Get-ReservedCoresLocal {
        param([int]$count)
        $keyPath = "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel"
        $valueName = "ReservedCpuSets"
        $reserved = New-Object bool[] $count

        if (Test-Path $keyPath) {
            $val = Get-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue
            if ($val -and $val.$valueName) {
                $bytes = $val.$valueName
                $bitIndex = 0
                for ($i = 0; $i -lt $bytes.Length; $i++) {
                    $byte = $bytes[$i]
                    for ($j = 0; $j -lt 8; $j++) {
                        if ($bitIndex -ge $count) { break }
                        $reserved[$bitIndex] = (($byte -band (1 -shl $j)) -ne 0)
                        $bitIndex++
                    }
                }
            }
        }
        return $reserved
    }

    function script:Apply-ReservedColoring {
        param([bool[]]$reservedArr)
        $colorDefault = [System.Drawing.Color]::FromArgb(219,219,219)
        $colorDim     = [System.Drawing.Color]::FromArgb(150,150,150)  
        $colorEffBlue = [System.Drawing.Color]::FromArgb(0,104,181)
        $colorReservedP = [System.Drawing.Color]::Yellow
        $colorReservedE = [System.Drawing.Color]::Green

        $colorCcd0      = [System.Drawing.Color]::Orange
        $colorCcd1      = [System.Drawing.Color]::Purple
        $colorCcd0Res   = [System.Drawing.Color]::Brown
        $colorCcd1Res   = [System.Drawing.Color]::Pink

        foreach ($device in $deviceList) {
            $ctrls = $deviceControls[$device]
            if (-not $ctrls) { continue }
            foreach ($chk in $ctrls.CheckBoxes) {
                $coreNum = [int]$chk.Tag
                if ($coreNum -ge $reservedArr.Length) { continue }
                $isReserved = $reservedArr[$coreNum]
                $affinityAllowed = $true
                try { $affinityAllowed = $chk.AutoCheck } catch { $affinityAllowed = $true }

                if ($script:IsDualCCDCpu) {
                    if ($script:Ccd0Cores -contains $coreNum) {
                        $chk.ForeColor = if ($isReserved) { $colorCcd0Res } else { $colorCcd0 }
                    } elseif ($script:Ccd1Cores -contains $coreNum) {
                        $chk.ForeColor = if ($isReserved) { $colorCcd1Res } else { $colorCcd1 }
                    } else {
                        $chk.ForeColor = if ($affinityAllowed) { $colorDefault } else { $colorDim }
                    }
                } else {
                    if ($isReserved) {
                        if (Is-PCore $coreNum) {
                            $chk.ForeColor = $colorReservedP
                        } else {
                            $chk.ForeColor = $colorReservedE
                        }
                    } else {
                        if (-not $affinityAllowed) {
                            $chk.ForeColor = $colorDim
                        } else {
                            if (Is-PCore $coreNum) {
                                $chk.ForeColor = $colorDefault
                            } else {
                                $chk.ForeColor = $colorEffBlue
                            }
                        }
                    }
                }
            }
        }
        foreach ($chk in $script:reservedCheckboxes) {
            $coreNum = [int]$chk.Tag
            if ($coreNum -ge $reservedArr.Length) { continue }
            $isReserved = $reservedArr[$coreNum]
            $affinityAllowed = $true
            try { $affinityAllowed = $chk.AutoCheck } catch { $affinityAllowed = $true }

            if ($script:IsDualCCDCpu) {
                if ($script:Ccd0Cores -contains $coreNum) {
                    $chk.ForeColor = if ($isReserved) { $colorCcd0Res } else { $colorCcd0 }
                } elseif ($script:Ccd1Cores -contains $coreNum) {
                    $chk.ForeColor = if ($isReserved) { $colorCcd1Res } else { $colorCcd1 }
                } else {
                    $chk.ForeColor = if ($affinityAllowed) { $colorDefault } else { $colorDim }
                }
            } else {
                if ($isReserved) {
                    if (Is-PCore $coreNum) {
                        $chk.ForeColor = $colorReservedP
                    } else {
                        $chk.ForeColor = $colorReservedE
                    }
                } else {
                    if (-not $affinityAllowed) {
                        $chk.ForeColor = $colorDim
                    } else {
                        if (Is-PCore $coreNum) {
                            $chk.ForeColor = $colorDefault
                        } else {
                            $chk.ForeColor = $colorEffBlue
                        }
                    }
                }
            }
        }
    }

    try {
        $initialReserved = script:Get-ReservedCoresLocal -count $logicalCount
    } catch {
        $initialReserved = New-Object bool[] $logicalCount
    }

    for ($col = 0; $col -lt $columns; $col++) {
        $startCPU = $col * $maxCoresPerColumn
        $endCPU = [Math]::Min($startCPU + $maxCoresPerColumn - 1, $logicalCount - 1)
        for ($row = 0; $row -lt ($endCPU - $startCPU + 1); $row++) {
            $cpuNumber = $startCPU + $row
            $chk = New-Object System.Windows.Forms.CheckBox

            $chk.Text = "CPU $cpuNumber"    
            $chk.Tag = $cpuNumber
            $chk.Width = 80
            $chk.Height = 20
            $chk.Left = 10 + $col * $columnWidth
            $chk.Top = $row * $rowHeight
            $chk.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
            $chk.FlatStyle = "Standard"
            $chk.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 9)

            if ($cpuNumber -lt $initialReserved.Length) {
                $chk.Checked = $initialReserved[$cpuNumber]
            }

            if (Is-PCore $cpuNumber) {
                $chk.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
            } else {
                $chk.ForeColor = [System.Drawing.Color]::FromArgb(0,104,181)
            }

            $reservedPanel.Controls.Add($chk)
            $script:reservedCheckboxes += $chk
        }
    }

    $btnSetReserved = New-Object System.Windows.Forms.Button
    $btnSetReserved.Text = "SET RESERVED CORES"
    $btnSetReserved.Width = 395
    $btnSetReserved.Height = 40
    $btnSetReserved.Left = 10
    $btnSetReserved.Top = $reservedPanel.Bottom + 12
    $btnSetReserved.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $btnSetReserved.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255)
    $btnSetReserved.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btnSetReserved.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $btnSetReserved.FlatAppearance.BorderSize = 1
    $btnSetReserved.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $reservedGroupBox.Controls.Add($btnSetReserved)

    $btnSetReserved.Add_MouseEnter({
        $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(234,234,234)
        $this.FlatAppearance.BorderSize = 1
        $this.Refresh()
    })
    $btnSetReserved.Add_MouseLeave({
        $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
        $this.FlatAppearance.BorderSize = 1
        $this.Refresh()
    })

    $btnSetReserved.Add_Click({
        $bytes = New-Object byte[] ([Math]::Ceiling($logicalCount / 8))

        foreach ($chk in $script:reservedCheckboxes) {
            $coreNum = [int]$chk.Tag
            if ($chk.Checked -and $coreNum -lt $logicalCount) {
                $byteIndex = [Math]::Floor($coreNum / 8)
                $bitIndex = $coreNum % 8
                $bytes[$byteIndex] = $bytes[$byteIndex] -bor (1 -shl $bitIndex)
            }
        }

        $keyPath = "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel"
        $valueName = "ReservedCpuSets"

        try {
            if (-not (Test-Path $keyPath)) {
                New-Item -Path $keyPath -Force | Out-Null
            }
            Set-ItemProperty -Path $keyPath -Name $valueName -Value $bytes -Type Binary -ErrorAction Stop

            try {
                $newReserved = script:Get-ReservedCoresLocal -count $logicalCount
            } catch {
                $newReserved = New-Object bool[] $logicalCount
            }
            script:Apply-ReservedColoring -reservedArr $newReserved

            [System.Windows.Forms.MessageBox]::Show("ReservedCpuSets updated successfully!", "Success", "OK", "Information")
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to update ReservedCpuSets: $_", "Error", "OK", "Error")
        }
    })

    try {
        script:Apply-ReservedColoring -reservedArr $initialReserved
    } catch {
    }

    return $reservedGroupBox.Bottom + 10
}

function Get-CurrentDevicePolicy($registryPath) {
    $relativePath = Get-RelativeRegistryPath $registryPath
    $targetSubkey = "$relativePath\Device Parameters\Interrupt Management\Affinity Policy"
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($targetSubkey, $false)
        if ($regKey -ne $null) {
            $val = $regKey.GetValue("DevicePolicy", $null)
            if ($val -ne $null) { return [int]$val }
        }
    } catch { }
    return 0  
}

function Set-DevicePolicy($registryPath, $policy) {
    $relativePath = Get-RelativeRegistryPath $registryPath
    $targetSubkey = "$relativePath\Device Parameters\Interrupt Management\Affinity Policy"
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey(
            $targetSubkey, 
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
        )
        if ($regKey -ne $null) {
            $regKey.SetValue("DevicePolicy", [int]$policy, [Microsoft.Win32.RegistryValueKind]::DWord)
            $regKey.Close()
            return $true
        }
    } catch { }
    return $false
}


$tempFontPath = [System.IO.Path]::Combine(
    [System.IO.Path]::GetTempPath(), 
    "CPMono_v07_Plain.ttf"
)
[System.IO.File]::WriteAllBytes($tempFontPath, $fontBytes)

$fontCollection = New-Object System.Drawing.Text.PrivateFontCollection
$fontCollection.AddFontFile($tempFontPath)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public static class CpuInfo
{
    public const int RelationProcessorCore = 0;
    public const int ERROR_INSUFFICIENT_BUFFER = 122;

    [StructLayout(LayoutKind.Sequential)]
    public struct GROUP_AFFINITY
    {
        public ulong Mask;
        public ushort Group;
        public ushort Reserved1;
        public uint Reserved2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESSOR_RELATIONSHIP
    {
        public byte Flags;
        public byte EfficiencyClass;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] Reserved;
        public ushort GroupCount;
        public GROUP_AFFINITY GroupMask;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
    {
        public int Relationship;
        public int Size;
        public PROCESSOR_RELATIONSHIP Processor;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetLogicalProcessorInformationEx(
        int RelationshipType,
        IntPtr Buffer,
        ref int ReturnedLength
    );

    public static Dictionary<int, byte> GetCoreEfficiencyClasses()
    {
        int bufferSize = 0;
        var result = new Dictionary<int, byte>();
        int processorCount = Environment.ProcessorCount;

        if (!GetLogicalProcessorInformationEx(RelationProcessorCore, IntPtr.Zero, ref bufferSize) &&
            Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
        {
            return result;
        }

        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetLogicalProcessorInformationEx(RelationProcessorCore, buffer, ref bufferSize))
            {
                int offset = 0;
                while (offset < bufferSize)
                {
                    var header = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)Marshal.PtrToStructure(
                        new IntPtr(buffer.ToInt64() + offset), 
                        typeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)
                    );

                    if (header.Relationship == RelationProcessorCore)
                    {
                        byte effClass = header.Processor.EfficiencyClass;
                        ulong mask = header.Processor.GroupMask.Mask;
                        ushort group = header.Processor.GroupMask.Group;

                        for (int i = 0; i < 64; i++)
                        {
                            if ((mask & (1UL << i)) != 0)
                            {
                                int globalIndex = (int)(group * 64 + i);
                                if (globalIndex < processorCount && !result.ContainsKey(globalIndex))
                                {
                                    result[globalIndex] = effClass;
                                }
                            }
                        }
                    }
                    offset += header.Size;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }
}
"@

$global:coreEfficiencyMap = [CpuInfo]::GetCoreEfficiencyClasses()

$script:CoreEffUniqueCount = ($global:coreEfficiencyMap.Values | Select-Object -Unique).Count
$script:CoreMapIsHomogeneous = ($script:CoreEffUniqueCount -le 1)

function Is-DualCCD {
    $cpuName = (Get-WmiObject Win32_Processor).Name
    $dualCCDModels = @(
        "Ryzen 9 7900X",
        "Ryzen 9 7950X",
        "Ryzen 9 9900X",
        "Ryzen 9 9950X",
        "Ryzen 9 5900X",
        "Ryzen 9 5950X"
    )
    foreach ($model in $dualCCDModels) {
        if ($cpuName -like "*$model*") {
            return $true
        }
    }
    return $false
}
$script:IsDualCCDCpu = Is-DualCCD
$script:LogicalCoreCount = [Environment]::ProcessorCount
if ($script:IsDualCCDCpu) {
    $script:Ccd0Cores = 0..([Math]::Floor($script:LogicalCoreCount / 2) - 1)
    $script:Ccd1Cores = [Math]::Ceiling($script:LogicalCoreCount / 2)..($script:LogicalCoreCount - 1)
} else {
    $script:Ccd0Cores = @()
    $script:Ccd1Cores = @()
}

function Is-PCore {
    param([int]$index)
    if ($script:CoreMapIsHomogeneous -or -not $global:coreEfficiencyMap.ContainsKey($index)) {
        return $true
    }
    return ($global:coreEfficiencyMap[$index] -eq 1)
}

function Get-PNPId($registryPath) {
    $cleanPath = $registryPath -replace "^(Microsoft\.PowerShell\.Core\\Registry::)?(H[Kk]LM:\\|Hkey[_]?Local[_]?Machine\\|HKEY_LOCAL_MACHINE\\|HKLM:\\)", ""
    $cleanPath = $cleanPath -replace "^(System\\CurrentControlSet\\Enum\\)", ""
    $cleanPath = $cleanPath -replace "\\\\", "\"
    $parts = $cleanPath -split '\\'
    if ($parts.Count -ge 2) {
        $deviceId = $parts[1]  
        $idComponents = $deviceId -split '&'
        $vendor = $idComponents | Where-Object { $_ -like "VEN_*" } | Select-Object -First 1
        $device = $idComponents | Where-Object { $_ -like "DEV_*" } | Select-Object -First 1
        $formattedId = "$($parts[0])_$(if ($vendor) { $vendor } else { 'UNKNOWN_VEN' })_$(if ($device) { $device } else { 'UNKNOWN_DEV' })"
        return $formattedId
    }
    return $cleanPath
}

function Optimized-TestAudioDeviceParents {
    $allDevices = Get-PnpDevice -ErrorAction SilentlyContinue
    $audioEndpoints = $allDevices |
        Where-Object { $_.Class -eq 'AudioEndpoint' -and $_.Status -eq 'OK' }

    try {
        $scriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { Get-Location }
    } catch { $scriptDir = Get-Location }
    $logDir = Join-Path $scriptDir 'logs'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $logFile = Join-Path $logDir 'logging.txt'
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }
    function Write-Log {
        param($text)
        $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Add-Content -Path $logFile -Value ("[$time] $text")
    }

    $getController = {
        param($instId)
        $current = $allDevices | Where-Object InstanceId -EQ $instId
        $lastUsb  = $null
        for ($depth = 0; $depth -lt 6 -and $current; $depth++) {
            $parentId = (Get-PnpDeviceProperty -InstanceId $current.InstanceId `
                         -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue).Data
            if (-not $parentId) { break }
            $current = $allDevices | Where-Object InstanceId -EQ $parentId
            if ($current.InstanceId -match 'PCI\\VEN_') {
                return Get-PNPId $current.InstanceId
            }
            elseif ($current.InstanceId -match 'USB\\') {
                $lastUsb = Get-PNPId $current.InstanceId
            }
        }
        return $lastUsb
    }

    foreach ($ep in $audioEndpoints) {
        $ctrlId = & $getController $ep.InstanceId

        switch -Wildcard ($ep.FriendlyName) {
            "*Headphone*"  { $type = "Headphones" }
            "*Microphone*" { $type = "Microphone" }
            "*Headset*"    { $type = "Headphones" }
            "*Earphone*"   { $type = "Headphones" }
            "*IEM*"        { $type = "Headphones" }
            "*Speaker*"    { $type = "Speakers" }
            default        { $type = "Audio" }  
        }

        try {
            $fn = if ($ep.FriendlyName) { $ep.FriendlyName } else { "<unknown>" }
            Write-Log "AudioEndpoint detected: FriendlyName='$fn' Type=$type ControllerID='$ctrlId'"
        } catch {}

        [PSCustomObject]@{
            AudioDevice  = $ep.FriendlyName
            AudioType    = $type
            ControllerID = $ctrlId
        }
    }
}

$audioParentsRaw = Optimized-TestAudioDeviceParents

$audioLookup = @{}

foreach ($row in $audioParentsRaw) {
    if ($row.ControllerID) {
        if (-not $audioLookup.ContainsKey($row.ControllerID)) {
            $audioLookup[$row.ControllerID] = [System.Collections.Generic.List[string]]::new()
        }
        $audioLookup[$row.ControllerID].Add($row.AudioType)
    }
}

function Get-RelativeRegistryPath($fullPath) {
    $path = $fullPath -replace "^Microsoft\.PowerShell\.Core\\Registry::", ""
    $path = $path -replace "^(HKLM:\\|HKEY_LOCAL_MACHINE\\)", ""
    return $path
}

function Get-RegistryInfo($deviceId) {
    $paths = @("HKLM:\SYSTEM\CurrentControlSet\Enum\$deviceId", "HKLM:\SYSTEM\ControlSet001\Enum\$deviceId")
    foreach ($path in $paths) {
        if (Test-Path $path) {
            try {
                $info = Get-ItemProperty -Path $path -ErrorAction Stop
                return @{ RegistryPath = $path; DeviceDesc = $info.DeviceDesc }
            }
            catch { continue }
        }
    }
    return @{ RegistryPath = "Not Found"; DeviceDesc = "Not Found" }
}

function Get-PciPortId($devicePath) {
    $parts = $devicePath -split '\\'
    if ($parts.Count -lt 3) { return $null }
    $lastPart = $parts[-1]
    $segments = $lastPart -split '&'
    if ($segments.Count -ge 3) { 
        return "$($segments[0])&$($segments[1])&$($segments[2])" 
    }
    return $null
}

function Is-GPU($deviceDesc) {
    return ($deviceDesc -match '(?i)(geforce|radeon)')
}

function Optimized-GetStorageDevices {
    $diskDrives = Get-PnpDevice -Class DiskDrive -ErrorAction SilentlyContinue |
                  Where-Object Status -eq 'OK'
    $regex = '(?i)(NVM|AHCI|SATA|SCSI|RAID)'

    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object {
        $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        if ($props.DeviceDesc -and $props.DeviceDesc -match $regex) {
            $controllerInstanceId = ($_.PSPath -split '\\Enum\\')[1]

            $hasConnectedDisks = $false
            foreach ($disk in $diskDrives) {
                $current = $disk
                for ($depth = 0; $depth -lt 5 -and $current; $depth++) {
                    $parentId = (Get-PnpDeviceProperty -InstanceId $current.InstanceId `
                                 -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue).Data
                    if (-not $parentId) { break }
                    if ($parentId -eq $controllerInstanceId) {
                        $hasConnectedDisks = $true
                        break
                    }
                    $current = Get-PnpDevice -InstanceId $parentId -ErrorAction SilentlyContinue
                }
                if ($hasConnectedDisks) { break }
            }

            if ($hasConnectedDisks) {
                $displayName = if ($props.DeviceDesc -match '(?i)NVMe?') { 'SSD (NVME)' } else { 'SSD (SATA)' }
                [PSCustomObject]@{
                    Category     = 'SSD'
                    Role         = 'Storage'
                    DisplayName  = $displayName
                    RegistryPath = $_.PSPath
                    Description  = $props.DeviceDesc
                }
            }
        }
    }
}

function Find-NetworkAdapterPCI($device) {
    $pciRoot = "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI"
    $devDesc = $device.Description
    if (-not $devDesc) { return $null }
    $pciDevices = Get-ChildItem -Path $pciRoot -Recurse -ErrorAction SilentlyContinue
    foreach ($item in $pciDevices) {
        try { $props = Get-ItemProperty -Path $item.PSPath -ErrorAction SilentlyContinue } catch { continue }
        if ($props -and $props.DeviceDesc) {
            $pciDesc = $props.DeviceDesc
            if (($pciDesc -like "*$devDesc*") -or ($devDesc -like "*$pciDesc*")) { return $item.PSPath }
        }
    }
    return $null
}

function Get-NetworkAdapterMSIRegistryPath($device) {
    if ($device.Category -eq "Network") {
         $pciKey = Find-NetworkAdapterPCI $device
         if ($pciKey -ne $null) { return $pciKey }
    }
    return $device.RegistryPath
}

function Get-NetworkAdapterAffinityRegistryPath($device) {
    if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") { return $device.RegistryPath }
    elseif ($device.Category -eq "Network" -and $device.Role -eq "NetAdapterCx") {
         $pciKey = Find-NetworkAdapterPCI $device
         if ($pciKey -ne $null) { return $pciKey } else { return $device.RegistryPath }
    } else { return $device.RegistryPath }
}

function Get-AffinityHexForCore($assignmentCore, $logicalCores) {
    $numDigits = $FixedByteLength * 2
    $fmt = "{0:X$numDigits}"
    return $fmt -f (1 -shl $assignmentCore)
}

function Calculate-AffinityHex($checkboxes) {
    $mask = 0
    foreach ($chk in $checkboxes) {
        if ($chk.Checked) {
            $coreNum = [int]$chk.Tag
            $mask = $mask -bor (1 -shl $coreNum)
        }
    }
    return "0x" + $mask.ToString("X")
}

function Set-CheckboxesFromAffinity($checkboxes, $affinityHex) {
    try { $maskInt = [Convert]::ToInt64($affinityHex, 16) } catch { $maskInt = 0 }
    foreach ($chk in $checkboxes) {
        $core = [int]$chk.Tag
        if (($maskInt -band (1 -shl $core)) -ne 0) { $chk.Checked = $true } else { $chk.Checked = $false }
    }
}

function Get-CurrentAffinity($registryPath, $isNDIS) {
    if ($isNDIS) {
        try {
            $relPath = Get-RelativeRegistryPath $registryPath
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($relPath, $false)
            if ($regKey -ne $null) {
                $value = $regKey.GetValue("*RssBaseProcNumber", $null)
                if ($value -ne $null) { return "0x" + ([int]$value).ToString("X") }
            }
        } catch { }
        return "0x0"
    } else {
        try {
            $relativePath = Get-RelativeRegistryPath $registryPath
            $targetSubkey = "$relativePath\Device Parameters\Interrupt Management\Affinity Policy"
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($targetSubkey, $false)
            if ($regKey -ne $null) {
                $value = $regKey.GetValue("AssignmentSetOverride", $null)
                if ($value -ne $null) {
                    if ($value -isnot [byte[]]) { $value = [byte[]]$value }
                    [Int64]$maskInt = 0
                    for ($i = 0; $i -lt $value.Length; $i++) {
                        $maskInt += ([int]$value[$i]) -shl (8*$i)
                    }
                    return "0x" + $maskInt.ToString("X")
                }
            }
        } catch { }
        return "0x0"
    }
}

function Get-CurrentNumRssQueues {
    param([string]$registryPath)

    $relativePath = Get-RelativeRegistryPath $registryPath
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($relativePath, $false)
        if ($regKey -ne $null) {
            $val = $regKey.GetValue("*NumRssQueues", $null)
            if ($null -ne $val) {
                return [int]$val
            }
        }
        return $null
    } 
    catch {
        return $null
    }
}

function Get-CurrentPriority($registryPath) {
    try {
        $relativePath = Get-RelativeRegistryPath $registryPath
        $targetSubkey = "$relativePath\Device Parameters\Interrupt Management\Affinity Policy"
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($targetSubkey, $false)
        if ($regKey -ne $null) {
            $val = $regKey.GetValue("DevicePriority", $null)
            if ($val -ne $null) { return [int]$val }
        }
    } catch { }
    return 2
}

function Set-DevicePriority($registryPath, $priority) {
    try {
        $relativePath = Get-RelativeRegistryPath $registryPath
        $targetSubkey = "$relativePath\Device Parameters\Interrupt Management\Affinity Policy"
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($targetSubkey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
        if ($regKey -ne $null) {
            $regKey.SetValue("DevicePriority", [int]$priority, [Microsoft.Win32.RegistryValueKind]::DWord)
            $regKey.Close()
            return $true
        }
    } catch { }
    return $false
}

function Get-CurrentMSI($registryPath) {
    $relativePath = Get-RelativeRegistryPath $registryPath
    $subkeyPath = "$relativePath\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subkeyPath, $false)
        if ($regKey -ne $null) {
            $msi = $regKey.GetValue("MSISupported", $null)
            $msgLimit = $regKey.GetValue("MessageNumberLimit", $null)
            if ($msi -eq $null) { $msi = 0 }
            if ($msgLimit -eq $null) { $msgLimit = "" }
            return @{ MSIEnabled = $msi; MessageLimit = $msgLimit }
        }
    } catch { }
    return @{ MSIEnabled = 0; MessageLimit = "" }
}

function Set-DeviceMSI($registryPath, $msiEnabled, $msgLimit) {
    $relativePath = Get-RelativeRegistryPath $registryPath
    $subkeyPath = "$relativePath\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
    try {
        $regKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($subkeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
        if ($regKey -ne $null) {
            $regKey.SetValue("MSISupported", [int]$msiEnabled, [Microsoft.Win32.RegistryValueKind]::DWord)
            if ($msgLimit -eq "" -or $msgLimit -eq "Unlimited" -or ([int]$msgLimit) -eq 0) {
                if ($regKey.GetValue("MessageNumberLimit", $null) -ne $null) {
                    $regKey.DeleteValue("MessageNumberLimit", $false)
                }
            }
            else {
                $regKey.SetValue("MessageNumberLimit", [int]$msgLimit, [Microsoft.Win32.RegistryValueKind]::DWord)
            }
            $regKey.Close()
            return $true
        }
    } catch { }
    return $false
}

function Set-DeviceAffinity($registryPath, $affinityHex) {
    $relativePath = Get-RelativeRegistryPath $registryPath
    $targetSubkey = "$relativePath\Device Parameters\Interrupt Management\Affinity Policy"
    
    try {
        $maskInt = [Convert]::ToInt64($affinityHex, 16)
        
        if ($maskInt -ne 0) {
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey(
                $targetSubkey, 
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
            )
            
            if ($regKey -ne $null) {
                $maskBytes = New-Object byte[] $FixedByteLength
                for ($i = 0; $i -lt $FixedByteLength; $i++) {
                    $maskBytes[$i] = ($maskInt -shr (8 * $i)) -band 0xFF
                }
                $regKey.SetValue("AssignmentSetOverride", $maskBytes, [Microsoft.Win32.RegistryValueKind]::Binary)
                $regKey.SetValue("DevicePolicy", 4, [Microsoft.Win32.RegistryValueKind]::DWord)
                $regKey.Close()
            }
        }
        return $true
    } 
    catch { 
        return $false
    }
}

function Get-HIDDevicesWithUSBControllers {
    $pnpCache = @{}
    function Resolve-DeviceInfo {
        param($instanceId)
        if (-not $pnpCache.ContainsKey($instanceId)) {
            $dev = Get-PnpDevice -InstanceId $instanceId -ErrorAction SilentlyContinue
            $friendly = if ($dev -and $dev.FriendlyName) { $dev.FriendlyName } else { $instanceId }
            $pnpCache[$instanceId] = @{ DeviceDesc = $friendly }
        }
        return $pnpCache[$instanceId]
    }

    function Get-DeviceTypeFromName {
        param([string]$productName)
        $name = $productName.ToLower()
        if ($name -match 'samson') { return $null }
        if ($name -eq "usb receiver") { return "Mouse" }
        if ($name -eq "usb device")  { return "Keyboard" }
        if ($name -eq "<none>")      { return "Keyboard" }
        if ($name -eq "wireless-receiver") { return "Mouse" }
        if ($name -match "usb gaming keyboard" -or $name -match "ctl") { return $null }

        $keyboardPatterns = @(
            "keyboard", "kbd", "kb", "he", "68", "75", "80", "63", "irok", "87", "96", "104", "820", "none",
            "60%", "65%", "tkl", "varmilo", "blackwidow", "keypad", "mechanical", "comard", "ak820",
            "cherry mx", "gateron", "keychron", "ducky", "leopold", "filco", "akko", "85",
            "gmmk", "iqunix", "nuphy", "apex pro", "k70", "k95", "optical switch", "RS",
            "75%", "fullsize", "tenkeyless", "macro pad", "keymap", "keycap", "switch"
        )

        $mousePatterns = @(
            "mouse", "ms", "8k", "2.4g", "4k", "pulsefire", "haste", "deathadder", "helios",
            "viper", "ajazz", "model o", "model d", "g pro", "g502", "g703", "g903", "Mad",
            "pulsar", "glorious", "zowie", "trackball", "sensor", "dpi", "gaming mouse",
            "g-wolves", "xm1", "skoll", "hsk", "viper mini", "orca", "superlight", "MCHOSE",
            "scroll wheel", "side button", "ergonomic", "ambidextrous", "fingertip", "MAJOR",
            "palm grip", "claw grip", "lod", "ips", "polling rate", "wlmouse", "xd"
        )

        $brandMapping = @{
            "varmilo"     = "Keyboard"
            "ajazz"       = "Mouse"
            "lamzu"       = "Mouse"
            "razer"       = "Mouse"
            "logitech"    = "Mouse"
            "steelseries" = "Mouse"
            "endgame"     = "Mouse"
            "finalmouse"  = "Mouse"
            "keychron"    = "Keyboard"
            "hexgears"    = "Keyboard"
            "ducky"       = "Keyboard"
            "leopold"     = "Keyboard"
            "filco"       = "Keyboard"
            "akko"        = "Keyboard"
            "iqunix"      = "Keyboard"
            "nuphy"       = "Keyboard"
            "corsair"     = "Keyboard"
            "hyperx"      = "Keyboard"
            "asus"        = "Keyboard"
            "msi"         = "Keyboard"
            "bloody"      = "Mouse"
            "roccat"      = "Mouse"
            "coolermaster"= "Keyboard"
        }

        $patternMatches = @{}
        foreach ($pattern in $keyboardPatterns) {
            try {
                $count = ([regex]::Matches($name, [regex]::Escape($pattern), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
                if ($count -gt 0) { $patternMatches[$pattern] = $count }
            } catch {}
        }
        foreach ($pattern in $mousePatterns) {
            try {
                $count = ([regex]::Matches($name, [regex]::Escape($pattern), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
                if ($count -gt 0) {
                    if ($patternMatches.ContainsKey($pattern)) { $patternMatches[$pattern] += $count } else { $patternMatches[$pattern] = $count }
                }
            } catch {}
        }
        foreach ($brand in $brandMapping.Keys) {
            try {
                $count = ([regex]::Matches($name, [regex]::Escape($brand), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
                if ($count -gt 0) {
                    if ($patternMatches.ContainsKey($brand)) { $patternMatches[$brand] += $count } else { $patternMatches[$brand] = $count }
                }
            } catch {}
        }

        $countKeyboard = 0
        $countMouse = 0
        foreach ($k in $patternMatches.Keys) {
            $c = $patternMatches[$k]
            if ($keyboardPatterns -contains $k) {
                $countKeyboard += $c
            } elseif ($mousePatterns -contains $k) {
                $countMouse += $c
            } elseif ($brandMapping.ContainsKey($k)) {
                if ($brandMapping[$k] -eq "Keyboard") { $countKeyboard += $c } else { $countMouse += $c }
            }
        }

        if ($countMouse -gt $countKeyboard) { return "Mouse" }
        if ($countKeyboard -gt $countMouse) { return "Keyboard" }

        $keyboardEvidence = $keyboardPatterns | Where-Object { $patternMatches.ContainsKey($_) }
        $mouseEvidence = $mousePatterns | Where-Object { $patternMatches.ContainsKey($_) }
        $brandEvidence = $brandMapping.Keys | Where-Object { $patternMatches.ContainsKey($_) }

        if ($keyboardEvidence.Count -gt 0 -and $mouseEvidence.Count -eq 0) { return "Keyboard" }
        if ($mouseEvidence.Count -gt 0 -and $keyboardEvidence.Count -eq 0) { return "Mouse" }

        foreach ($brand in $brandEvidence) {
            $mapped = $brandMapping[$brand]
            if ($mapped -eq "Keyboard") { return "Keyboard" }
            if ($mapped -eq "Mouse")    { return "Mouse" }
        }

        foreach ($pattern in $keyboardPatterns) {
            if ($name -like "*$pattern*") { return "Keyboard" }
        }
        foreach ($pattern in $mousePatterns) {
            if ($name -like "*$pattern*") { return "Mouse" }
        }

        return $null
    }

    Add-Type -TypeDefinition @"
using System; using System.Text; using System.Runtime.InteropServices;
public class HidInterop {
    public const int DIGCF_PRESENT = 0x2;
    public const int DIGCF_DEVICEINTERFACE = 0x10;
    public static readonly Guid GUID_DEVINTERFACE_HID = new Guid("4D1E55B2-F16F-11CF-88CB-001111000030");
    [StructLayout(LayoutKind.Sequential)] public struct SP_DEVICE_INTERFACE_DATA {
        public int cbSize; public Guid InterfaceClassGuid; public int Flags; public IntPtr Reserved;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct SP_DEVICE_INTERFACE_DETAIL_DATA {
        public int cbSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string DevicePath;
    }
    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern IntPtr SetupDiGetClassDevs(
        ref Guid ClassGuid, IntPtr Enumerator, IntPtr hwndParent, int Flags);
    [DllImport("setupapi.dll", SetLastError = true)]
    public static extern bool SetupDiEnumDeviceInterfaces(
        IntPtr DeviceInfoSet, IntPtr DeviceInfoData, ref Guid InterfaceClassGuid,
        int MemberIndex, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);
    [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool SetupDiGetDeviceInterfaceDetail(
        IntPtr DeviceInfoSet, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
        ref SP_DEVICE_INTERFACE_DETAIL_DATA DeviceInterfaceDetailData,
        int DeviceInterfaceDetailDataSize, out int RequiredSize, IntPtr DeviceInfoData);
    [DllImport("hid.dll", SetLastError = true)]
    public static extern bool HidD_GetProductString(
        IntPtr HidDeviceObject, byte[] Buffer, int BufferLength);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

    try {
        $scriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { Get-Location }
    } catch {
        $scriptDir = Get-Location
    }
    $logDir = Join-Path $scriptDir 'logs'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $logFile = Join-Path $logDir 'logging.txt'
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }

    function Write-LogLocal { param($txt) $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Add-Content -Path $logFile -Value "[$time] $txt" }

    $guid    = [HidInterop]::GUID_DEVINTERFACE_HID
    $flags   = [HidInterop]::DIGCF_PRESENT -bor [HidInterop]::DIGCF_DEVICEINTERFACE
    $devInfo = [HidInterop]::SetupDiGetClassDevs([ref]$guid, [IntPtr]::Zero, [IntPtr]::Zero, $flags)
    if ($devInfo -eq [IntPtr]::Zero) { return @() }

    $index = 0
    $results = @()
    $unmatchedDevices = @()
    $productStats = @{}

    while ($true) {
        $iface = New-Object HidInterop+SP_DEVICE_INTERFACE_DATA
        $iface.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($iface)
        if (-not [HidInterop]::SetupDiEnumDeviceInterfaces($devInfo, [IntPtr]::Zero, [ref]$guid, $index, [ref]$iface)) {
            break
        }

        $detail       = New-Object HidInterop+SP_DEVICE_INTERFACE_DETAIL_DATA
        $detail.cbSize = if ([IntPtr]::Size -eq 8) { 8 } else { 5 }
        [int]$reqSize = 0
        if (-not [HidInterop]::SetupDiGetDeviceInterfaceDetail(
                $devInfo, [ref]$iface, [ref]$detail,
                [Runtime.InteropServices.Marshal]::SizeOf($detail),
                [ref]$reqSize, [IntPtr]::Zero)) {
            $index++; continue
        }
        $devicePath = $detail.DevicePath

        $handle  = [HidInterop]::CreateFile($devicePath,0,3,[IntPtr]::Zero,3,0,[IntPtr]::Zero)
        $product = "<none>"
        if ($handle -ne [IntPtr]::Zero -and $handle -ne -1) {
            $buf = New-Object Byte[] 256
            if ([HidInterop]::HidD_GetProductString($handle, $buf, $buf.Length)) {
                $product = [Text.Encoding]::Unicode.GetString($buf).Trim([char]0)
            }
            [HidInterop]::CloseHandle($handle) | Out-Null
        }

        try { Write-LogLocal "HID Device detected: ProductString='$product'" } catch {}

        $deviceType = Get-DeviceTypeFromName -productName $product

        $name = $product.ToLower()
        if ($name -match 'samson') {
            try { Write-LogLocal "Ignoring Samson device: $product" } catch {}
            $index++
            continue
        }

        $patternDetails = @{ }

        $klist = @(
            "keyboard", "kbd", "kb", "he", "68", "75", "80", "63", "irok", "87", "96", "104", "none",
            "60%", "65%", "tkl", "varmilo", "blackwidow", "keypad", "mechanical", "comard",
            "cherry mx", "gateron", "keychron", "ducky", "leopold", "filco", "akko",
            "gmmk", "iqunix", "nuphy", "apex pro", "k70", "k95", "optical switch", "RS",
            "75%", "fullsize", "tenkeyless", "macro pad", "keymap", "keycap", "switch"
        )
        $mlist = @(
            "mouse", "ms", "8k", "2.4g", "4k", "pulsefire", "haste", "deathadder", "helios",
            "viper", "ajazz", "model o", "model d", "g pro", "g502", "g703", "g903", "MAD",
            "pulsar", "glorious", "zowie", "trackball", "sensor", "dpi", "gaming mouse",
            "g-wolves", "xm1", "skoll", "hsk", "viper mini", "orca", "superlight",
            "scroll wheel", "side button", "ergonomic", "ambidextrous", "fingertip",
            "palm grip", "claw grip", "lod", "ips", "polling rate", "wlmouse", "xd", "MAJOR"
        )
        $brandMap = @{
            "varmilo"     = "Keyboard"
            "ajazz"       = "Mouse"
            "lamzu"       = "Mouse"
            "razer"       = "Mouse"
            "logitech"    = "Mouse"
            "steelseries" = "Mouse"
            "endgame"     = "Mouse"
            "finalmouse"  = "Mouse"
            "keychron"    = "Keyboard"
            "hexgears"    = "Keyboard"
            "ducky"       = "Keyboard"
            "leopold"     = "Keyboard"
            "filco"       = "Keyboard"
            "akko"        = "Keyboard"
            "iqunix"      = "Keyboard"
            "nuphy"       = "Keyboard"
            "corsair"     = "Keyboard"
            "hyperx"      = "Keyboard"
            "asus"        = "Keyboard"
            "msi"         = "Keyboard"
            "bloody"      = "Mouse"
            "roccat"      = "Mouse"
            "coolermaster"= "Keyboard"
        }

        foreach ($p in $klist) {
            try {
                $c = ([regex]::Matches($name, [regex]::Escape($p), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
                if ($c -gt 0) { $patternDetails[$p] = $c }
            } catch {}
        }
        foreach ($p in $mlist) {
            try {
                $c = ([regex]::Matches($name, [regex]::Escape($p), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
                if ($c -gt 0) {
                    if ($patternDetails.ContainsKey($p)) { $patternDetails[$p] += $c } else { $patternDetails[$p] = $c }
                }
            } catch {}
        }
        foreach ($p in $brandMap.Keys) {
            try {
                $c = ([regex]::Matches($name, [regex]::Escape($p), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
                if ($c -gt 0) {
                    if ($patternDetails.ContainsKey($p)) { $patternDetails[$p] += $c } else { $patternDetails[$p] = $c }
                }
            } catch {}
        }

        if ($patternDetails.Count -gt 0) {
            $detailStrings = $patternDetails.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }

            $mappingList = @()
            foreach ($k in $patternDetails.Keys) {
                if ($klist -contains $k) {
                    $mappingList += "$k=Keyboard"
                } elseif ($mlist -contains $k) {
                    $mappingList += "$k=Mouse"
                } elseif ($brandMap.ContainsKey($k)) {
                    $mappingList += "$k=$($brandMap[$k])"
                } else {
                    $mappingList += "$k=Unknown"
                }
            }

            try { Write-LogLocal "  Pattern matches: $($detailStrings -join '; ')" } catch {}
            try { Write-LogLocal "  Pattern -> Type mapping: $($mappingList -join '; ')" } catch {}

            $countKeyboard = 0
            $countMouse = 0
            foreach ($k in $patternDetails.Keys) {
                $c = $patternDetails[$k]
                if ($klist -contains $k) {
                    $countKeyboard += $c
                } elseif ($mlist -contains $k) {
                    $countMouse += $c
                } elseif ($brandMap.ContainsKey($k)) {
                    if ($brandMap[$k] -eq "Keyboard") { $countKeyboard += $c } else { $countMouse += $c }
                }
            }
            try { Write-LogLocal "  Totals => Keyboard=$countKeyboard Mouse=$countMouse" } catch {}
        } else {
            try { Write-LogLocal "  Pattern matches: <none>" } catch {}
            $unmatchedDevices += [PSCustomObject]@{ Product = $product }
        }

        if (-not $deviceType) {
            try { Write-LogLocal "  Determined DeviceType: <none>" } catch {}
        } else {
            try { Write-LogLocal "  Determined DeviceType: $deviceType" } catch {}
        }

        if (-not $productStats.ContainsKey($product)) {
            $productStats[$product] = @{
                Occurrences = 0
                Classification = @{ Keyboard = 0; Mouse = 0; None = 0 }
                TotalPatternMatches = 0
                PatternTotals = @{}
            }
        }
        $productStats[$product].Occurrences++
        $classKey = if ($deviceType) { $deviceType } else { 'None' }
        $productStats[$product].Classification[$classKey]++
        $sumMatches = 0
        foreach ($k in $patternDetails.Keys) {
            $c = $patternDetails[$k]
            $sumMatches += $c
            if (-not $productStats[$product].PatternTotals.ContainsKey($k)) { $productStats[$product].PatternTotals[$k] = 0 }
            $productStats[$product].PatternTotals[$k] += $c
        }
        $productStats[$product].TotalPatternMatches += $sumMatches

        $inst = if ($devicePath -match '^\\\\\?\\hid#([^#]+)#') {
            ($Matches[1] -replace '#','\').ToUpper()
        } else { $null }

        $ctrls = @()
        if ($inst) {
            Get-WmiObject Win32_USBControllerDevice -ErrorAction SilentlyContinue |
              Where-Object { $_.Dependent -match [regex]::Escape($inst) } |
              ForEach-Object {
                  $cid  = ([regex]::Match($_.Antecedent,'DeviceID="([^"]+)"')).Groups[1].Value
                  $info = Resolve-DeviceInfo $cid
                  $ctrls += [PSCustomObject]@{
                      ControllerPNPID = $cid
                      ControllerName  = $info.DeviceDesc
                  }
              }
            $ctrls = $ctrls | Sort-Object ControllerPNPID -Unique
        }

        $results += [PSCustomObject]@{
            ProductString    = $product
            DeviceType       = $deviceType
            DevicePath       = $devicePath
            DeviceInstanceID = $inst
            USBControllers   = if ($ctrls) { $ctrls } else { $null }
            PatternDetails   = $patternDetails
            MatchTotal       = if ($patternDetails.Values) { ($patternDetails.Values | Measure-Object -Sum).Sum } else { 0 }
        }

        $index++
    }

    if ($productStats.Keys.Count -gt 0) {
        try { Write-LogLocal "SUMMARY: HID product statistics (aggregated by ProductString):" } catch {}
        foreach ($prod in $productStats.Keys) {
            $entry = $productStats[$prod]
            $occ = $entry.Occurrences
            $kbd = $entry.Classification.Keyboard
            $ms  = $entry.Classification.Mouse
            $n   = $entry.Classification.None
            $totalMatches = $entry.TotalPatternMatches
            try { Write-LogLocal "  - Product='$prod' Occurrences=$occ Keyboard=$kbd Mouse=$ms None=$n TotalPatternMatches=$totalMatches" } catch {}
            if ($entry.PatternTotals.Keys.Count -gt 0) {
                $pt = $entry.PatternTotals.GetEnumerator() | Sort-Object -Property Value -Descending | ForEach-Object { "$($_.Key)=$($_.Value)" }
                try { Write-LogLocal "      PatternTotals: $($pt -join '; ')" } catch {}
            }
        }
    } else {
        try { Write-LogLocal "SUMMARY: No HID products detected." } catch {}
    }

    return $results
}

function Get-USBControllers {
    $assocs = Get-WmiObject Win32_USBControllerDevice -ErrorAction SilentlyContinue

    $pnpCache = @{}
    function Resolve-DeviceInfo {
        param($instanceId)
        if (-not $pnpCache.ContainsKey($instanceId)) {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$instanceId"
            if (Test-Path $regPath) {
                $desc = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).DeviceDesc
                $pnpCache[$instanceId] = @{ RegistryPath = $regPath; DeviceDesc = $desc }
            } else {
                $w = Get-PnpDevice -InstanceId $instanceId -ErrorAction SilentlyContinue
                $friendly = if ($w -and $w.FriendlyName) { $w.FriendlyName } else { $instanceId }
                $pnpCache[$instanceId] = @{ RegistryPath = "PNP:$instanceId"; DeviceDesc = $friendly }
            }
        }
        return $pnpCache[$instanceId]
    }

    try {
        $scriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { Get-Location }
    } catch { $scriptDir = Get-Location }
    $logDir = Join-Path $scriptDir 'logs'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $logFile = Join-Path $logDir 'logging.txt'
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }

    function Write-LogLocal { param($txt) $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Add-Content -Path $logFile -Value "[$time] $txt" }

    try {
        $lines = Get-Content -Path $logFile -ErrorAction SilentlyContinue
        if ($lines) {
            $out = New-Object System.Collections.Generic.List[string]
            $seenAssigned = @{}
            foreach ($line in $lines) {
                if ($line -match 'Get-USBControllers: Assigned audio role ''?([^'']+)''? to controller ''?([^'']+)''?') {
                    $role = $Matches[1]
                    $controller = $Matches[2]
                    $key = "$controller|$role"
                    if (-not $seenAssigned.ContainsKey($key)) {
                        $seenAssigned[$key] = $true
                        $out.Add($line)
                    } else {
                    }
                } else {
                    $out.Add($line)
                }
            }
            if ($out.Count -ne $lines.Count) {
                Set-Content -Path $logFile -Value $out -Encoding UTF8
                Write-LogLocal "Get-USBControllers: Cleaned duplicate historical 'Assigned audio role' log entries."
            }
        }
    } catch {}

    $hidDevices = Get-HIDDevicesWithUSBControllers
    $hidRoleMap = @{}
    $productAggregation = @{}

    foreach ($device in $hidDevices) {
        if (-not $device.USBControllers) { continue }

        $prod = $device.ProductString
        if (-not $productAggregation.ContainsKey($prod)) {
            $productAggregation[$prod] = @{
                Occurrences = 0
                Classification = @{ Keyboard = 0; Mouse = 0; None = 0 }
                TotalPatternMatches = 0
                PatternTotals = @{}
            }
        }
        $productAggregation[$prod].Occurrences++
        $ck = if ($device.DeviceType) { $device.DeviceType } else { 'None' }
        $productAggregation[$prod].Classification[$ck]++
        $mt = 0
        try { $mt = [int]$device.MatchTotal } catch {}
        $productAggregation[$prod].TotalPatternMatches += $mt
        if ($device.PatternDetails) {
            foreach ($k in $device.PatternDetails.Keys) {
                $c = $device.PatternDetails[$k]
                if (-not $productAggregation[$prod].PatternTotals.ContainsKey($k)) { $productAggregation[$prod].PatternTotals[$k] = 0 }
                $productAggregation[$prod].PatternTotals[$k] += $c
            }
        }

        foreach ($controller in $device.USBControllers) {
            $pnpId = Get-PNPId $controller.ControllerPNPID
            if (-not $hidRoleMap.ContainsKey($pnpId)) {
                $hidRoleMap[$pnpId] = @{
                    Keyboard = $false
                    Mouse    = $false
                }
            }
            if ($device.DeviceType -eq 'Keyboard') {
                $hidRoleMap[$pnpId].Keyboard = $true
            } elseif ($device.DeviceType -eq 'Mouse') {
                $hidRoleMap[$pnpId].Mouse = $true
            }
        }
    }

    $controllerMap = @{}
    $loggedRoleKeys = @{}    

    foreach ($assoc in $assocs) {
        $ctrlId = ([regex]::Match($assoc.Antecedent, 'DeviceID="([^"]+)"')).Groups[1].Value
        $devId  = ([regex]::Match($assoc.Dependent,  'DeviceID="([^"]+)"')).Groups[1].Value
        $ctrlKey = Get-PNPId $ctrlId
        $ctrlInfo = Resolve-DeviceInfo $ctrlId

        if (-not $controllerMap.ContainsKey($ctrlKey)) {
            $controllerMap[$ctrlKey] = @{
                RegistryPath = $ctrlInfo.RegistryPath
                Description  = $ctrlInfo.DeviceDesc
                Roles        = [System.Collections.Generic.HashSet[string]]::new()
            }
        }

        $devInfo = Resolve-DeviceInfo $devId
        if ($devInfo.DeviceDesc -match '(?i)game controller|Xbox') {
            $controllerMap[$ctrlKey].Roles.Add('Controller') | Out-Null
        }

        if ($audioLookup -and $audioLookup.ContainsKey($ctrlKey)) {
            foreach ($atype in $audioLookup[$ctrlKey] | Select-Object -Unique) {
                if (-not $controllerMap[$ctrlKey].Roles.Contains($atype)) {
                    $controllerMap[$ctrlKey].Roles.Add($atype) | Out-Null
                    $logKey = "$ctrlKey|$atype"
                    if (-not $loggedRoleKeys.ContainsKey($logKey)) {
                        $loggedRoleKeys[$logKey] = $true
                        try {
                            Write-LogLocal "Get-USBControllers: Assigned audio role '$atype' to controller '$ctrlKey' (desc='$($controllerMap[$ctrlKey].Description)')"
                        } catch {}
                    }
                } else {
                }
            }
        }
    }

    foreach ($ctrlKey in $hidRoleMap.Keys) {
        if (-not $controllerMap.ContainsKey($ctrlKey)) { continue }
        if ($hidRoleMap[$ctrlKey].Keyboard) {
            if (-not $controllerMap[$ctrlKey].Roles.Contains('Keyboard')) {
                $controllerMap[$ctrlKey].Roles.Add('Keyboard') | Out-Null
                $logKey = "$ctrlKey|Keyboard"
                if (-not $loggedRoleKeys.ContainsKey($logKey)) {
                    $loggedRoleKeys[$logKey] = $true
                    Write-LogLocal "Get-USBControllers: Assigned HID role 'Keyboard' to controller '$ctrlKey' (desc='$($controllerMap[$ctrlKey].Description)')"
                }
            }
        }
        if ($hidRoleMap[$ctrlKey].Mouse) {
            if (-not $controllerMap[$ctrlKey].Roles.Contains('Mouse')) {
                $controllerMap[$ctrlKey].Roles.Add('Mouse') | Out-Null
                $logKey = "$ctrlKey|Mouse"
                if (-not $loggedRoleKeys.ContainsKey($logKey)) {
                    $loggedRoleKeys[$logKey] = $true
                    Write-LogLocal "Get-USBControllers: Assigned HID role 'Mouse' to controller '$ctrlKey' (desc='$($controllerMap[$ctrlKey].Description)')"
                }
            }
        }
    }

    try {
        Write-LogLocal "Get-USBControllers: Final controller map collected for GUI:"
        foreach ($entry in $controllerMap.GetEnumerator()) {
            $key = $entry.Key
            $desc = $entry.Value.Description
            $roles = if ($entry.Value.Roles.Count -gt 0) { ($entry.Value.Roles | Sort-Object | ForEach-Object { $_ }) -join '/' } else { '<none>' }
            Write-LogLocal "  Controller='$key' Roles='$roles' Path='$($entry.Value.RegistryPath)' Desc='$desc'"
        }
    } catch {}

    $usbDevices = @()
    foreach ($entry in $controllerMap.GetEnumerator()) {
        $rolesArr = @()
        foreach ($r in $entry.Value.Roles) { $rolesArr += $r }
        if ($rolesArr.Count -eq 0) { continue }
        $usbDevices += [PSCustomObject]@{
            Category     = 'USB'
            Roles        = $rolesArr
            DisplayName  = "USB Host Controller (" + ($rolesArr -join "/") + ")"
            RegistryPath = $entry.Value.RegistryPath
            Description  = $entry.Value.Description
        }
    }

    return $usbDevices
}

function Get-AudioEndpointMappings {
    $allDevices = Get-PnpDevice -ErrorAction SilentlyContinue
    $controllers = $allDevices | Where-Object { 
        $_.FriendlyName -like '*Audio Controller*' -and $_.Status -eq 'OK' 
    }
    $endpoints = Get-PnpDevice -Class AudioEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' }

    try {
        $scriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { Get-Location }
    } catch { $scriptDir = Get-Location }
    $logDir = Join-Path $scriptDir 'logs'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $logFile = Join-Path $logDir 'logging.txt'
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }
    function Write-Log {
        param($text)
        $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Add-Content -Path $logFile -Value ("[$time] $text")
    }

    $controllerMap = @{}
    foreach ($ep in $endpoints) {
        $parent1 = Get-PnpDeviceProperty -InstanceId $ep.InstanceId -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue
        if (-not $parent1) { continue }
        
        $parent2 = Get-PnpDeviceProperty -InstanceId $parent1.Data -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue
        if (-not $parent2) { continue }

        $controller = $controllers | Where-Object { $_.InstanceId -eq $parent2.Data }
        if (-not $controller) { continue }

        $type = "Unknown Audio Device"
        if ($ep.FriendlyName -match 'headphone|headset|earphone|iem') { $type = "Headphones" }
        elseif ($ep.FriendlyName -match 'microphone|mic') { $type = "Microphone" }
        elseif ($ep.FriendlyName -match 'speaker|dynamic') { $type = "Speakers" }

        $pnpId = Get-PNPId $controller.InstanceId
        if (-not $controllerMap.ContainsKey($pnpId)) {
            $controllerMap[$pnpId] = @{
                Types = @()
                Descriptions = @()
            }
        }
        if ($type -ne "Unknown Audio Device") {
            $controllerMap[$pnpId].Types += $type
            $controllerMap[$pnpId].Descriptions += $ep.FriendlyName
            try {
                $fn = if ($ep.FriendlyName) { $ep.FriendlyName } else { "<unknown>" }
                Write-Log "Audio mapping: ControllerPNP='$pnpId' EndpointName='$fn' MatchedType='$type'"
            } catch {}
        } else {
            try {
                $fn = if ($ep.FriendlyName) { $ep.FriendlyName } else { "<unknown>" }
                Write-Log "Audio mapping: ControllerPNP='$pnpId' EndpointName='$fn' MatchedType='Unknown'"
            } catch {}
        }
    }

    return $controllerMap
}

function Get-PCIDevices {
    $pciRoot   = 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI'
    $allPciKey = Get-ChildItem -Path $pciRoot -Recurse -ErrorAction SilentlyContinue

    $pciDescMap = @{}
    foreach ($key in $allPciKey) {
        $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
        if ($props.DeviceDesc) {
            $pciDescMap[$key.PSPath] = $props.DeviceDesc
        }
    }

    try {
        $scriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { Get-Location }
    } catch { $scriptDir = Get-Location }
    $logDir = Join-Path $scriptDir 'logs'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $logFile = Join-Path $logDir 'logging.txt'
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }

    function Write-LogLocal { param($txt) $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Add-Content -Path $logFile -Value "[$time] $txt" }

    $gpuPorts   = New-Object System.Collections.Generic.HashSet[string]
    $gpuDevices = @()
    foreach ($psPath in $pciDescMap.Keys) {
        $desc = $pciDescMap[$psPath]
        if ($desc -match '(?i)(geforce|radeon)') {
            $segments = ($psPath -split '\\')[-1] -split '&'
            $portId   = $segments[0..2] -join '&'
            $gpuPorts.Add($portId) | Out-Null
            $gpuDevices += [PSCustomObject]@{
                Category    = 'PCI'
                Role        = 'GPU'
                DisplayName = 'GPU'
                RegistryPath= $psPath
                Description = $desc
                Port        = $portId
            }
            try { Write-LogLocal "Get-PCIDevices: GPU detected: Path='$psPath' Port='$portId' Desc='$desc'" } catch {}
        }
    }

    $audioMappings = $audioLookup   
    $audioDevices  = @()
    $ignoredAudio  = @()

    foreach ($psPath in $pciDescMap.Keys) {
        $desc = $pciDescMap[$psPath]

        if ($desc -match '(?i)Audio Controller') {
            $segments = ($psPath -split '\\')[-1] -split '&'
            $portId   = $segments[0..2] -join '&'
            $pnpId    = Get-PNPId $psPath

            if ($audioMappings -and $audioMappings.ContainsKey($pnpId)) {
                $types = $audioMappings[$pnpId] |
                         Where-Object { $_ -ne 'Unknown Audio Device' } |
                         Sort-Object -Unique
                if ($types.Count) {
                    $display = 'Audio (Audio Controller) - ' + ($types -join '/')
                    $audioDevices += [PSCustomObject]@{
                        Category    = 'PCI'
                        Role        = 'Audio'
                        DisplayName = $display
                        RegistryPath= $psPath
                        Description = $desc
                        Port        = $portId
                        AudioTypes  = $types
                        PNPID       = $pnpId
                    }
                    try { Write-LogLocal "Get-PCIDevices: INCLUDED Audio controller -> PNPID='$pnpId' Path='$psPath' Port='$portId' Desc='$desc' Types='$(if ($types) { $types -join '/' } else { '<none>' })'" } catch {}
                } else {
                    $ignoredAudio += @{ Path = $psPath; PNPID = $pnpId; Desc = $desc; Reason = "Mapped but no usable audio types" }
                    try { Write-LogLocal "Get-PCIDevices: IGNORED Audio controller (mapped but no usable types) -> PNPID='$pnpId' Path='$psPath' Desc='$desc'" } catch {}
                }
            } else {
                $ignoredAudio += @{ Path = $psPath; PNPID = $pnpId; Desc = $desc; Reason = "No audio endpoint mapping found" }
                try { Write-LogLocal "Get-PCIDevices: IGNORED Audio controller (no mapping) -> PNPID='$pnpId' Path='$psPath' Desc='$desc'" } catch {}
            }
        }
    }

    foreach ($a in $audioDevices) {
        if ($a.Port -and $gpuPorts.Contains($a.Port) -and $a.AudioTypes -and $a.AudioTypes.Count -gt 0) {
            $oldDisplay = $a.DisplayName
            $a.DisplayName = 'Audio - GPU'
            $a.Role        = 'AudioGPU'
            try { Write-LogLocal "Get-PCIDevices: Audio controller upgraded to Audio-GPU -> PNPID='$($a.PNPID)' Path='$($a.RegistryPath)' Port='$($a.Port)' OldDisplay='$oldDisplay' NewDisplay='Audio - GPU'" } catch {}
        }
    }

    try {
        Write-LogLocal "Get-PCIDevices: Summary - GPUs found: $($gpuDevices.Count), Audio controllers included: $($audioDevices.Count), Audio controllers ignored: $($ignoredAudio.Count)"
        if ($audioDevices.Count -gt 0) {
            foreach ($ad in $audioDevices) {
                $types = if ($ad.AudioTypes -and $ad.AudioTypes.Count -gt 0) { ($ad.AudioTypes -join '/') } else { '<none>' }
                Write-LogLocal "  Included Audio: PNPID='$($ad.PNPID)' Path='$($ad.RegistryPath)' Port='$($ad.Port)' Desc='$($ad.Description)' Types='$types'"
            }
        }
        if ($ignoredAudio.Count -gt 0) {
            foreach ($ia in $ignoredAudio) {
                Write-LogLocal "  Ignored Audio: PNPID='$($ia.PNPID)' Path='$($ia.Path)' Desc='$($ia.Desc)' Reason='$($ia.Reason)'"
            }
        }
    } catch {}

    return @{
        GPU   = $gpuDevices
        Audio = $audioDevices
    }
}

function Get-NetworkAdapters {
    $svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'

    $anyCx = Get-ChildItem -Path $svcRoot -ErrorAction SilentlyContinue |
             Where-Object {
                 $_.PSChildName -ne 'rtcx21' -and
                 (Get-ItemProperty -Path $_.PSPath -Name 'DisplayName' -ErrorAction SilentlyContinue).DisplayName -match 'NetAdapter' -and
                 (Test-Path -Path "$($_.PSPath)\Enum" -ErrorAction SilentlyContinue)
             } |
             Select-Object -First 1

    $useCx = $anyCx -ne $null

    $classKey    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
    $adapterKeys = Get-ChildItem -Path $classKey -ErrorAction SilentlyContinue

    try {
        $scriptDir = if ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { Get-Location }
    } catch { $scriptDir = Get-Location }
    $logDir = Join-Path $scriptDir 'logs'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $logFile = Join-Path $logDir 'logging.txt'
    if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File -Force | Out-Null }
    function Write-LogLocal { param($txt) $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Add-Content -Path $logFile -Value "[$time] $txt" }

    $out = @()

    function ProviderPrefixedPath($pspath) {
        if (-not $pspath) { return $null }
        return $pspath
    }

    function Find-EnumInstancePathForDriverDesc($driverDesc) {
        if (-not $driverDesc) { return $null }

        $pciRoot = 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI'
        try {
            $pciCandidates = Get-ChildItem -Path $pciRoot -Recurse -ErrorAction SilentlyContinue
            foreach ($p in $pciCandidates) {
                try {
                    $pp = Get-ItemProperty -Path $p.PSPath -ErrorAction SilentlyContinue
                    if ($pp) {
                        $candidateDesc = $pp.DeviceDesc
                        if ($candidateDesc) {
                            if ($candidateDesc -like "*$driverDesc*" -or $driverDesc -like "*$candidateDesc*") {
                                return $p.PSPath
                            }
                        }
                    }
                } catch {}
            }
        } catch {}

        $enumRoot = 'HKLM:\SYSTEM\CurrentControlSet\Enum'
        try {
            $enumCandidates = Get-ChildItem -Path $enumRoot -Recurse -ErrorAction SilentlyContinue
            foreach ($e in $enumCandidates) {
                try {
                    $ep = Get-ItemProperty -Path $e.PSPath -ErrorAction SilentlyContinue
                    if ($ep) {
                        $candidateDesc = $ep.DeviceDesc
                        if (-not $candidateDesc) { $candidateDesc = $ep.DriverDesc }
                        if ($candidateDesc) {
                            if ($candidateDesc -like "*$driverDesc*" -or $driverDesc -like "*$candidateDesc*") {
                                return $e.PSPath
                            }
                        }
                    }
                } catch {}
            }
        } catch {}

        return $null
    }

    foreach ($key in $adapterKeys) {
        $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
        if (-not $props -or -not $props.DriverDesc) { continue }

        if ($props.DriverDesc -notmatch '(?i)Intel|Marvell|Mellanox|Broadcom|Realtek') { continue }

        if ($props.DriverDesc -match '(?i)Intel' -and $props.DriverDesc -match '(?i)LPC|SMBUS|HD|Serial|Xeon|Series|Advanced|ME|PCI|Smart|VirtualBox|VMware|Shared|SRAM|DRAM|GNA|GPIO|PEG10|SPI|Monitoring') {
            continue
        }

        if ($useCx) {
            $role    = 'NetAdapterCx'
            $display = 'Network Interface Card (NetAdapterCx)'
        } else {
            $role    = 'NDIS'
            $display = 'Network Interface Card (NDIS)'
        }

        $classPath = $key.PSPath

        $enumPath = $null
        try {
            $enumPath = Find-EnumInstancePathForDriverDesc -driverDesc $props.DriverDesc
        } catch {}

        $configPath = if ($enumPath) { $enumPath } else { $classPath }

        $entry = [PSCustomObject]@{
            Category     = 'Network'
            Role         = $role
            DisplayName  = $display
            RegistryPath = $classPath                 
            Description  = $props.DriverDesc
            ConfigPath   = $configPath                
        }

        $out += $entry

        try {
            Write-LogLocal "Get-NetworkAdapters: Detected network adapter -> Name='$($props.DriverDesc)' Role='$role'"
            Write-LogLocal "  ClassPath: $($classPath)"
            Write-LogLocal "  ConfigPath: $($configPath)"
        } catch {}
    }

    $pciRoot = 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI'
    $pciKeys = Get-ChildItem -Path $pciRoot -Recurse -ErrorAction SilentlyContinue

    foreach ($pciKey in $pciKeys) {
        try {
            $pciProps = Get-ItemProperty -Path $pciKey.PSPath -ErrorAction Stop
        }
        catch {
            continue
        }

        if (-not $pciProps.DeviceDesc) { continue }

        if ($pciProps.DeviceDesc -notmatch '(?i)Intel|Marvell|Mellanox|Broadcom|Realtek') { continue }

        if ($pciProps.DeviceDesc -match '(?i)Intel' -and $pciProps.DeviceDesc -match '(?i)LPC|SMBUS|HD|Serial|Xeon|Series|Advanced|ME|PCI|Smart|VirtualBox|VMware|Shared|SRAM|DRAM|GNA|GPIO|PEG10|SPI|Monitoring') {
            continue
        }

        $cleanDesc = if ($pciProps.DeviceDesc -match ';') {
            $pciProps.DeviceDesc.Split(';')[-1].Trim()
        } else {
            $pciProps.DeviceDesc
        }

        if ($out | Where-Object { $_.Description -eq $cleanDesc }) { continue }

        if ($useCx) {
            $role    = 'NetAdapterCx'
            $display = 'Network Interface Card (NetAdapterCx)'
        } else {
            $role    = 'NDIS'
            $display = 'Network Interface Card (NDIS)'
        }

        $entry = [PSCustomObject]@{
            Category     = 'Network'
            Role         = $role
            DisplayName  = $display
            RegistryPath = $pciKey.PSPath           
            Description  = $cleanDesc
            ConfigPath   = $pciKey.PSPath
        }

        $out += $entry

        try {
            Write-LogLocal "Get-NetworkAdapters: Detected PCI network adapter -> Name='$cleanDesc' Role='$role'"
            Write-LogLocal "  PCIPath: $($pciKey.PSPath)"
            Write-LogLocal "  ConfigPath: $($pciKey.PSPath)"
        } catch {}
    }

    try {
        Write-LogLocal "Get-NetworkAdapters: Summary - Network adapters detected: $($out.Count)."
        foreach ($a in $out) {
            Write-LogLocal "  Detected Adapter: Name='$($a.Description)' Role='$($a.Role)' ClassPath='$($a.RegistryPath)' ConfigPath='$($a.ConfigPath)'"
        }
    } catch {}

    return $out
}

$deviceList = @()
$deviceList += Get-USBControllers
$pciDevices = Get-PCIDevices

if ($pciDevices.GPU) { $deviceList += $pciDevices.GPU }

if ($pciDevices.Audio) {
    $deviceList += $pciDevices.Audio | Where-Object { $_.AudioTypes -and ($_.AudioTypes.Count -gt 0) }
}
$deviceList += Get-NetworkAdapters
$deviceList += Optimized-GetStorageDevices

$deviceControls = @{}

$globalDeviceAddressMap = Get-Device-Addresses

function Refresh-DeviceUI {
    foreach ($device in $deviceList) {
        $ctrls = $deviceControls[$device]
        if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") {
            $affinityPath = $device.RegistryPath
        }
        elseif ($device.Category -eq "Network" -and $device.Role -eq "NetAdapterCx") {
            $affinityPath = Get-NetworkAdapterAffinityRegistryPath $device
        }
        else {
            $affinityPath = $device.RegistryPath
        }
        $newVal = Get-CurrentAffinity $affinityPath ($device.Category -eq "Network" -and $device.Role -eq "NDIS")
        $ctrls.InitialValue = $newVal
        if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") {
            try {
                $selectedBase = [Convert]::ToInt32($newVal,16)
            } catch {
                $selectedBase = -1
            }
            $numQueues = 1
            try { $numQueues = Get-CurrentNumRssQueues $affinityPath } catch { $numQueues = 1 }

            if ($numQueues -lt 1) { $numQueues = 1 }

            $logicalCount = [Environment]::ProcessorCount

            $selectedSet = @()
            if ($selectedBase -ge 0) {
                for ($i = 0; $i -lt $numQueues; $i++) {
                    $c = ($selectedBase + $i) % $logicalCount
                    $selectedSet += $c
                }
            }

            $script:NDISUpdating = $true
            foreach ($chk in $ctrls.CheckBoxes) {
                $core = [int]$chk.Tag
                if ($selectedSet -contains $core) {
                    $chk.Checked = $true
                    $chk.AutoCheck = $false   
                } else {
                    $chk.Checked = $false
                    $chk.AutoCheck = $true
                }
            }
            $script:NDISUpdating = $false

            if ($selectedBase -ge 0) {
                $maskInt = 0
                foreach ($c in $selectedSet) { $maskInt = $maskInt -bor (1 -shl $c) }
                $displayVal = "0x" + ([Convert]::ToString($maskInt,16)).ToUpper()
            } else {
                $displayVal = "0x0"
            }

            if ($ctrls.ContainsKey('NumQueues') -and $ctrls.NumQueues -ne $null) {
                try { $ctrls.NumQueues.Value = $numQueues } catch {}
                $ctrls.NumQueues.Visible = $true
            }
        } else {
            Set-CheckboxesFromAffinity $ctrls.CheckBoxes $newVal
            $displayVal = $newVal
            if ($ctrls.ContainsKey('NumQueues') -and $ctrls.NumQueues -ne $null) {
                $ctrls.NumQueues.Visible = $false
            }
        }
        $ctrls.MaskLabel.Text = "Affinity Mask: "
        $ctrls.MaskValue.Text = $displayVal
        $ctrls.MaskValue.ForeColor = [System.Drawing.Color]::FromArgb(255,100,45)
        
        if ($device.Category -eq "Network") {
            $msiPath = Get-NetworkAdapterMSIRegistryPath $device
        } else {
            $msiPath = $device.RegistryPath
        }
        $msi = Get-CurrentMSI $msiPath
        if ($msi.MSIEnabled -eq 1) {
            $ctrls.MSICombo.SelectedIndex = 1
        } else {
            $ctrls.MSICombo.SelectedIndex = 0
        }
        if ($msi.MessageLimit -eq "") {
            $ctrls.MsgLimitBox.Text = "Unlimited"
        }
        else {
            $ctrls.MsgLimitBox.Text = $msi.MessageLimit.ToString()
        }
        if ($device.Category -eq "Network") {
            $priPath = Get-NetworkAdapterMSIRegistryPath $device
        } else {
            $priPath = $device.RegistryPath
        }
        $priority = Get-CurrentPriority $priPath
        switch ($priority) {
            1 { $ctrls.PriorityCombo.SelectedIndex = 0 }
            2 { $ctrls.PriorityCombo.SelectedIndex = 1 }
            3 { $ctrls.PriorityCombo.SelectedIndex = 2 }
            default { $ctrls.PriorityCombo.SelectedIndex = 1 }
        }

        if (-not ($device.Category -eq "Network" -and $device.Role -eq "NDIS")) {
            $policy = Get-CurrentDevicePolicy $device.RegistryPath
            $ctrls.PolicyCombo.SelectedIndex = $policy
            
        $enableAffinity = ($policy -eq 4)  
        foreach ($chk in $ctrls.CheckBoxes) {
            $chk.AutoCheck = $enableAffinity
            $chk.Enabled   = $true
        }

        try {
            $reservedArr = script:Get-ReservedCoresLocal -count ([Environment]::ProcessorCount)
            script:Apply-ReservedColoring -reservedArr $reservedArr
        } catch { }
        }

    }
}

function Get-FreeCore {
    param(
        [int[]]$occupiedCores,
        [int]  $logicalCount
    )
    $occupied = @{}
    $occupiedCores | ForEach-Object { $occupied[$_] = $true }
    for ($i = 1; $i -lt $logicalCount; $i++) {
        if (-not $occupied.ContainsKey($i)) { return $i }
    }
    return (if (-not $occupied.ContainsKey(0)) { 0 } else { -1 })
}

function Update-ConfigFile {
    param (
        [string]$filePath,
        [string]$coresString,
        [int]   $mouseCore = -1,
        [int]   $dwmCore   = -1
    )
    $content = if (Test-Path $filePath) {
        Get-Content $filePath -Raw -Encoding UTF8  
    } else {
        ""
    }

    if ($dwmCore -ge 0 -and $filePath -like '*system_priorities.cfg') {
        $content = $content -replace 'threaddesc=DWM Kernel Sensor Thread, \(.*?\)',
                                     "threaddesc=DWM Kernel Sensor Thread, ($dwmCore)"
        $content = $content -replace 'threaddesc=DWM Master Input Thread, \(.*?\)',
                                     "threaddesc=DWM Master Input Thread, ($mouseCore)"
    }

    $content = $content -replace '(?m)^occupied_affinity_cores=.*$',
                                 "occupied_affinity_cores=$coresString"
    $content = $content -replace '(?m)^occupied_ideal_processor_cores=.*$',
                                 "occupied_ideal_processor_cores=$coresString"

    if ($content -notmatch 'occupied_affinity_cores=') {
        $content += "`r`noccupied_affinity_cores=$coresString"
    }
    if ($content -notmatch 'occupied_ideal_processor_cores=') {
        $content += "`r`noccupied_ideal_processor_cores=$coresString"
    }

    Set-Content -Path $filePath -Value $content.Trim() -Encoding UTF8
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "DEVICE-TWEAKER"
$form.Size = New-Object System.Drawing.Size(770,1000)  
$form.StartPosition = "CenterScreen"
$form.AutoScroll = $true
$form.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)

$panel = New-Object System.Windows.Forms.Panel
$panel.Dock = "Fill"
$panel.AutoScroll = $true
$panel.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
$panel.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
$form.Controls.Add($panel)

$iconBytes = [Convert]::FromBase64String($base64Icon)
$stream = New-Object System.IO.MemoryStream($iconBytes, $false)
$icon = New-Object System.Drawing.Icon($stream)
$form.Icon = $icon

$lblTitlePart1 = New-Object System.Windows.Forms.Label
$lblTitlePart1.Text = "DEVICE-TWEAKER BY "
$lblTitlePart1.AutoSize = $true
$lblTitlePart1.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 26)
$lblTitlePart1.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
$lblTitlePart1.Left = 12
$lblTitlePart1.Top = 40
$panel.Controls.Add($lblTitlePart1)

$lblTitlePart2 = New-Object System.Windows.Forms.Label
$lblTitlePart2.Text = "adii3584_ on discord"
$lblTitlePart2.AutoSize = $true
$lblTitlePart2.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 34)
$lblTitlePart2.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
$lblTitlePart2.Left = $lblTitlePart1.Right
$lblTitlePart2.Top = 40
$panel.Controls.Add($lblTitlePart2)

$lblHTStatus = New-Object System.Windows.Forms.Label
$lblHTStatus.Text = $htStatus
$lblHTStatus.AutoSize = $true
$lblHTStatus.Font = New-Object System.Drawing.Font($fontCollection.Families[0],22)
$lblHTStatus.ForeColor = $htColor
$lblHTStatus.Left = $lblHT.Right
$lblHTStatus.Top = $lnkGaming.Bottom + 26
$panel.Controls.Add($lblHTStatus)





$hoverColor = [System.Drawing.Color]::FromArgb(255,100,45)
$linkLabels = @($lnkTitlePart2, $lnkService, $lnkGuides, $lnkGaming, $lnkPills)
foreach ($lnk in $linkLabels) {
    $lnk.Add_MouseLeave({ $this.LinkColor = [System.Drawing.Color]::FromArgb(0,116,222) })
}

$cpu = Get-WmiObject Win32_Processor | Select-Object -First 1
$logicalCount = [Environment]::ProcessorCount
$physicalCount = $cpu.NumberOfCores
if ($logicalCount -gt $physicalCount) { 
    $htStatus = "Enabled"
    $htColor = [System.Drawing.Color]::FromArgb(255,100,45)
} else { 
    $htStatus = "Disabled"
    $htColor = [System.Drawing.Color]::FromArgb(255,100,45)
}



$btnApply = New-Object System.Windows.Forms.Button
$btnApply.Text = "APPLY"
$btnApply.Width = 191
$btnApply.Height = 40
$btnApply.Left = 20
$btnApply.Top = $lblHTStatus.Bottom + 16
$btnApply.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
$btnApply.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255)
$btnApply.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnApply.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
$btnApply.FlatAppearance.BorderSize = 1
$btnApply.Font = New-Object System.Drawing.Font($fontCollection.Families[0],11)
$panel.Controls.Add($btnApply)

$btnApply.Add_MouseEnter({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(234,234,234)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})

$btnApply.Add_MouseLeave({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})

$btnAutoOpt = New-Object System.Windows.Forms.Button
$btnAutoOpt.Text = "AUTO-OPTIMIZATION"
$btnAutoOpt.Width = 191
$btnAutoOpt.Height = 40
$btnAutoOpt.Left = $btnApply.Right + 10
$btnAutoOpt.Top = $btnApply.Top
$btnAutoOpt.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
$btnAutoOpt.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255)
$btnAutoOpt.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnAutoOpt.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
$btnAutoOpt.FlatAppearance.BorderSize = 1
$btnAutoOpt.Font = New-Object System.Drawing.Font($fontCollection.Families[0],11)
$panel.Controls.Add($btnAutoOpt)

$btnAutoOpt.Add_MouseEnter({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(234,234,234)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})

$btnAutoOpt.Add_MouseLeave({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})

$btnIRQ = New-Object System.Windows.Forms.Button
$btnIRQ.Text = "CALCULATE IRQ COUNTS"
$btnIRQ.Width = 281
$btnIRQ.Height = 40
$btnIRQ.Left = $btnAutoOpt.Right + 23
$btnIRQ.Top = $btnAutoOpt.Top
$btnIRQ.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
$btnIRQ.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255)
$btnIRQ.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnIRQ.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
$btnIRQ.FlatAppearance.BorderSize = 1
$btnIRQ.Font = New-Object System.Drawing.Font($fontCollection.Families[0],11)
$panel.Controls.Add($btnIRQ)

$btnIRQ.Add_MouseEnter({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(234,234,234)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})

$btnIRQ.Add_MouseLeave({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})

$btnIRQ.Add_Click({
    $btnIRQ.Enabled = $false
    $btnIRQ.Text = "Calculating..."
    $btnIRQ.Refresh()
    
    try {
        $irqCounts = Get-DeviceIRQCounts
        
        foreach ($device in $deviceList) {
            $ctrls = $deviceControls[$device]
            $pnpId = $ctrls.PNPID
            
            if ($irqCounts.ContainsKey($pnpId)) {
                $ctrls.IRQValueLabel.Text = "$($irqCounts[$pnpId])"
                $ctrls.IRQValueLabel.ForeColor = [System.Drawing.Color]::FromArgb(255,100,45)
            }
            else {
                $ctrls.IRQValueLabel.Text = "0"
                $ctrls.IRQValueLabel.ForeColor = [System.Drawing.Color]::FromArgb(255,100,45)
            }
        }
        
        [System.Windows.Forms.MessageBox]::Show("IRQ counts calculated successfully!", "Done", "OK", "Information")
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error calculating IRQ counts: $_", "Error", "OK", "Error")
    }
    finally {
        $btnIRQ.Enabled = $true
        $btnIRQ.Text = "CALCULATE IRQ COUNTS"
    }
})

$linkLabelTop = $lnkTitlePart2.Bottom + 15
$hoverColor = [System.Drawing.Color]::FromArgb(255, 100, 45)
$deviceBoxSpacing = 6

function Create-DeviceGroupBox($device, [int]$topPosition) {
    $groupBox = New-Object System.Windows.Forms.GroupBox
    $groupBox.Text = $device.DisplayName
    $groupBox.Width = 716
    if ($device.Category -eq "USB") {
        $groupBox.Height = 385  
    } else {
    $groupBox.Height = 340
    $groupBox.Height = 340
        $groupBox.Height = 340
    }
    $groupBox.Left = 10
    $groupBox.Top = $topPosition
    $groupBox.Tag = $device
    $groupBox.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $groupBox.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $groupBox.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    
    $affPanel = New-Object System.Windows.Forms.Panel
    $affPanel.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $affPanel.BorderStyle = "FixedSingle"
    $affPanel.Width = 395
    $affPanel.Height = 210
    $affPanel.Left = 10
    $affPanel.Top = 20
    $affPanel.AutoScroll = $true
    $affPanel.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $groupBox.Controls.Add($affPanel)
    
        
    $coreCount = [Environment]::ProcessorCount
    $checkboxes = @()
    $maxCoresPerColumn = 8  
    $columns = [Math]::Ceiling($coreCount / $maxCoresPerColumn)
    $columnWidth = 100
    $rowHeight = 25
    for ($col = 0; $col -lt $columns; $col++) {
        $startCPU = $col * $maxCoresPerColumn
        $endCPU = [Math]::Min($startCPU + $maxCoresPerColumn - 1, $coreCount - 1)
        for ($row = 0; $row -lt ($endCPU - $startCPU + 1); $row++) {
            $cpuNumber = $startCPU + $row
$chk = New-Object System.Windows.Forms.CheckBox
$chk.Text = "CPU $cpuNumber"
$chk.Tag = $cpuNumber
$chk.Width = 80
$chk.Left = 10 + $col * $columnWidth
$chk.Top = $row * $rowHeight

if (Is-PCore $cpuNumber) {
    $chk.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
} else {
    $chk.ForeColor = [System.Drawing.Color]::FromArgb(0,104,181)
}

$chk.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
$chk.FlatStyle = "Standard"
$chk.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 9)
            $affPanel.Controls.Add($chk)
            $checkboxes += $chk
        }
    }
    
    $lblMask = New-Object System.Windows.Forms.Label
    $lblMask.AutoSize = $true
    $lblMask.Left = 7
    $lblMask.Top = $affPanel.Bottom + 15
    $lblMask.Text = "Affinity Mask: "
    $lblMask.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $lblMask.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $groupBox.Controls.Add($lblMask)
    
    if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") {
        $affinityPath = $device.RegistryPath
    }
    elseif ($device.Category -eq "Network" -and $device.Role -eq "NetAdapterCx") {
        $affinityPath = Get-NetworkAdapterAffinityRegistryPath $device
    }
    else {
        $affinityPath = $device.RegistryPath
    }
    $initialValue = Get-CurrentAffinity $affinityPath ($device.Category -eq "Network" -and $device.Role -eq "NDIS")
    if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") {
        try { 
            $selectedBase = [Convert]::ToInt32($initialValue,16) 
        } catch { 
            $selectedBase = -1 
        }
        
        $numQueues = Get-CurrentNumRssQueues -registryPath $device.RegistryPath
        if (-not $numQueues -or $numQueues -lt 1) { $numQueues = 1 }
        
        $logicalCount = [Environment]::ProcessorCount
        $selectedSet = @()
        if ($selectedBase -ge 0) {
            for ($i = 0; $i -lt $numQueues; $i++) {
                $coreIndex = ($selectedBase + $i) % $logicalCount
                $selectedSet += $coreIndex
            }
        }
        
        foreach ($chk in $checkboxes) {
            $coreNum = [int]$chk.Tag
            $chk.Checked = ($selectedSet -contains $coreNum)
        }
    } else {
        Set-CheckboxesFromAffinity $checkboxes $initialValue
    }
    $lblMask.Text = "Affinity Mask:"
    $lblMaskValue = New-Object System.Windows.Forms.Label
    $lblMaskValue.AutoSize = $true
    $lblMaskValue.Left = $lblMask.Right + 7
    $lblMaskValue.Top = $lblMask.Top
    if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") {
        if ($selectedBase -ge 0) {
            $maskInt = 0
            for ($i = 0; $i -lt $numQueues; $i++) {
                $coreIndex = ($selectedBase + $i) % $logicalCount
                $maskInt = $maskInt -bor (1 -shl $coreIndex)
            }
            $lblMaskValue.Text = "0x" + $maskInt.ToString("X")
        } else {
            $lblMaskValue.Text = "0x0"
        }
    } else {
        $lblMaskValue.Text = $initialValue
    }
    $lblMaskValue.ForeColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $lblMaskValue.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $groupBox.Controls.Add($lblMaskValue)
    
    if ($device.Category -eq "SSD") {
        $lblNote = New-Object System.Windows.Forms.Label
        $lblNote.Text = "(Affinity doesn't work for SSD)"
        $lblNote.ForeColor = [System.Drawing.Color]::FromArgb(219,25,25)
        $lblNote.AutoSize = $true
        $lblNote.Left = 112
        $lblNote.Top = $lblPNP.Top 
        $lblNote.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
        $groupBox.Controls.Add($lblNote)
    }
    
    $msiPanel = New-Object System.Windows.Forms.Panel
    $msiPanel.Width = 282
    $msiPanel.Height = if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") { 165 } else { 163 }    
    $msiPanel.Left = $affPanel.Right + 20
    $msiPanel.Top = 20
    $msiPanel.BorderStyle = "FixedSingle"
    $msiPanel.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $groupBox.Controls.Add($msiPanel)
    
    $lblMSI = New-Object System.Windows.Forms.Label
    $lblMSI.Text = "MSI Mode:"
    $lblMSI.AutoSize = $true
    $lblMSI.Left = 10
    $lblMSI.Top = 10
    $lblMSI.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $lblMSI.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $msiPanel.Controls.Add($lblMSI)
    
    $cboMSI = New-Object System.Windows.Forms.ComboBox
    $cboMSI.Left = 150
    $cboMSI.Top = 5
    $cboMSI.Width = 120
    $cboMSI.DropDownStyle = "DropDownList"
    $cboMSI.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $cboMSI.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $cboMSI.FlatStyle = "Flat"
    $cboMSI.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 12)
    $cboMSI.Items.Add("Disabled")
    $cboMSI.Items.Add("Enabled")
    $msiPanel.Controls.Add($cboMSI)
    
    $lblMsg = New-Object System.Windows.Forms.Label
    $lblMsg.Text = "MSI Limit:"
    $lblMsg.AutoSize = $true
    $lblMsg.Left = 10
    $lblMsg.Top = $lblMSI.Bottom + 20
    $lblMsg.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $msiPanel.Controls.Add($lblMsg)
    
    $msgLimitBox = New-Object System.Windows.Forms.TextBox
    $msgLimitBox.Left = 150
    $msgLimitBox.Top = $lblMSI.Bottom + 17
    $msgLimitBox.Width = 103
    $msgLimitBox.BorderStyle = "FixedSingle"
    $msgLimitBox.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $msgLimitBox.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $msgLimitBox.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 12)
    $msiPanel.Controls.Add($msgLimitBox)
    
    $lblPri = New-Object System.Windows.Forms.Label
    $lblPri.Text = "IRQ Priority:"
    $lblPri.AutoSize = $true
    $lblPri.Left = 10
    $lblPri.Top = $lblMsg.Bottom + 20
    $lblPri.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $msiPanel.Controls.Add($lblPri)
    
    $cboPriority = New-Object System.Windows.Forms.ComboBox
    $cboPriority.Left = 150
    $cboPriority.Top = $lblMsg.Bottom + 15
    $cboPriority.Width = 120
    $cboPriority.DropDownStyle = "DropDownList"
    $cboPriority.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $cboPriority.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $cboPriority.FlatStyle = "Flat"
    $cboPriority.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 12)
    $cboPriority.Items.Add("Low")
    $cboPriority.Items.Add("Normal")
    $cboPriority.Items.Add("High")
    $msiPanel.Controls.Add($cboPriority)
    
    if ($device.Category -eq "Network") {
        $msiPath = Get-NetworkAdapterMSIRegistryPath $device
    } else {
        $msiPath = $device.RegistryPath
    }
    $msi = Get-CurrentMSI $msiPath
    if ($msi.MSIEnabled -eq 1) {
        $cboMSI.SelectedIndex = 1
    } else {
        $cboMSI.SelectedIndex = 0
    }
    if ($msi.MessageLimit -eq "") {
        $msgLimitBox.Text = "Unlimited"
    } else {
        $msgLimitBox.Text = $msi.MessageLimit.ToString()
    }
    $priority = Get-CurrentPriority $msiPath
    switch ($priority) {
        1 { $cboPriority.SelectedIndex = 0 }
        2 { $cboPriority.SelectedIndex = 1 }
        3 { $cboPriority.SelectedIndex = 2 }
        default { $cboPriority.SelectedIndex = 1 }
    }

    $isNDIS = ($device.Category -eq "Network" -and $device.Role -eq "NDIS")

    $lblNumQueues = New-Object System.Windows.Forms.Label
    $lblNumQueues.Text = "RSS Queues:"
    $lblNumQueues.AutoSize = $true
    $lblNumQueues.Left = 10
    $lblNumQueues.Top = $lblPri.Bottom + 15
    $lblNumQueues.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $lblNumQueues.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $lblNumQueues.Visible = $isNDIS  
    $msiPanel.Controls.Add($lblNumQueues)

    $nudNumQueues = New-Object System.Windows.Forms.NumericUpDown
    $nudNumQueues.Left = $lblNumQueues.Right + 27
    $nudNumQueues.Top = $lblNumQueues.Top + -6
    $nudNumQueues.Width = 45
    $nudNumQueues.Minimum = 1
    $nudNumQueues.Maximum = [Environment]::ProcessorCount
    $nudNumQueues.Value = 1
    $nudNumQueues.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 12)
    $nudNumQueues.BorderStyle = 'FixedSingle'
    $nudNumQueues.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $nudNumQueues.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)  
    $nudNumQueues.Visible = $isNDIS

    $currentNumQueues = Get-CurrentNumRssQueues -registryPath $device.RegistryPath
    if ($null -ne $currentNumQueues -and $currentNumQueues -ge 1) {
        $nudNumQueues.Value = $currentNumQueues
    } else {
        $nudNumQueues.Value = 1
    }

    $msiPanel.Controls.Add($nudNumQueues)

    $nudNumQueues.Add_ValueChanged({
        if ($script:NDISUpdating) { return }
        $parentGroup = $this.Parent.Parent
        $dev = $parentGroup.Tag
        $ctrls = $deviceControls[$dev]
        if (-not $ctrls) { return }
        $selectedBase = $null
        foreach ($cb in $ctrls.CheckBoxes) { if ($cb.Checked) { $selectedBase = [int]$cb.Tag; break } }
        if ($selectedBase -eq $null) { return }

        $numQueuesLocal = [int]$this.Value
        if ($numQueuesLocal -lt 1) { $numQueuesLocal = 1 }

        $logicalCount = [Environment]::ProcessorCount
        $selectedSet = @()
        for ($i=0; $i -lt $numQueuesLocal; $i++) {
            $c = ($selectedBase + $i) % $logicalCount
            $selectedSet += $c
        }

        $script:NDISUpdating = $true
        foreach ($cb in $ctrls.CheckBoxes) {
            $core = [int]$cb.Tag
            if ($selectedSet -contains $core) {
                $cb.Checked = $true
                $cb.AutoCheck = $false
            } else {
                $cb.Checked = $false
                $cb.AutoCheck = $true
            }
        }
        $script:NDISUpdating = $false

        $maskInt = 0
        foreach ($c in $selectedSet) { $maskInt = $maskInt -bor (1 -shl $c) }
        $ctrls.MaskValue.Text = "0x" + ([Convert]::ToString($maskInt,16)).ToUpper()
    })

    if ($device.Category -eq "Network") {
        $msiPathForPNP = Get-NetworkAdapterMSIRegistryPath $device
    } else {
        $msiPathForPNP = $device.RegistryPath
    }
    $pnpID = Get-PNPId $msiPathForPNP

if (-not ($device.Category -eq "Network" -and $device.Role -eq "NDIS")) {
    $lblPolicy = New-Object System.Windows.Forms.Label
    $lblPolicy.Text = "Policy:"
    $lblPolicy.AutoSize = $true
    $lblPolicy.Left = 10
    $lblPolicy.Top = $cboPriority.Bottom + 20
    $lblPolicy.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $msiPanel.Controls.Add($lblPolicy)

    $cboPolicy = New-Object System.Windows.Forms.ComboBox
    $cboPolicy.Left = 90
    $cboPolicy.Top = $lblPolicy.Top + -5
    $cboPolicy.Width = 180
    $cboPolicy.DropDownStyle = "DropDownList"
    $cboPolicy.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
    $cboPolicy.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $cboPolicy.FlatStyle = "Flat"
    $cboPolicy.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 12)
$cboPolicy.Items.AddRange(@(
    "MachineDefault",   # MachineDefault 
    "AllCloseCPU",      # AllCloseProcessors 
    "OneCloseCPU",      # OneCloseProcessor 
    "AllCPUInMach",     # AllProcessorsInMachine 
    "SpecCPU",          # SpecifiedProcessors 
    "SpreadMsgsCPU",    # SpreadMessagesAcrossAllProcessors 
    "AllCPUInMachSt"    # AllProcessorsInMachineWhenSteered 
))


    $msiPanel.Controls.Add($cboPolicy)
    
    $policyValue = Get-CurrentDevicePolicy $device.RegistryPath
    $cboPolicy.SelectedIndex = $policyValue
    
    $enableAffinity = ($policyValue -eq 4)  
    foreach ($chk in $checkboxes) {
        $chk.AutoCheck = $enableAffinity
        $chk.Enabled   = $true
    }

    try {
        $reservedArr = script:Get-ReservedCoresLocal -count ([Environment]::ProcessorCount)
        script:Apply-ReservedColoring -reservedArr $reservedArr
    } catch { }
    
    $cboPolicy.Add_SelectedIndexChanged({
        $enableAffinityNow = ($this.SelectedIndex -eq 4)  
        $parentGroup = $this.Parent.Parent
        $dev = $parentGroup.Tag
        $ctrls = $deviceControls[$dev]

        foreach ($chk in $ctrls.CheckBoxes) {
            $chk.AutoCheck = $enableAffinityNow
            $chk.Enabled   = $true
        }

        try {
            $reservedArr = script:Get-ReservedCoresLocal -count ([Environment]::ProcessorCount)
            script:Apply-ReservedColoring -reservedArr $reservedArr
        } catch { }
    })
}

$lblPNP = New-Object System.Windows.Forms.Label
$lblPNP.AutoSize = $true
$lblPNP.Left = 6
$lblPNP.Top = $lblMask.Bottom + 10
$lblPNP.Text = "PNP ID: "
$lblPNP.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
$lblPNP.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
$groupBox.Controls.Add($lblPNP)

$currentLeft = $lblPNP.Right

if ($pnpID -match '^([^_]+)(_VEN_)([^_]+)(_DEV_)([^_]+)(.*)$') {
    $busType = $matches[1]
    $venPrefix = $matches[2]
    $vendorId = $matches[3]
    $devPrefix = $matches[4]
    $deviceId = $matches[5]
    $remainder = $matches[6]
    
    $font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $offset = -4  
    
    $lblBusType = New-Object System.Windows.Forms.Label
    $lblBusType.Left = $currentLeft
    $lblBusType.Top = $lblPNP.Top
    $lblBusType.Text = $busType
    $lblBusType.Font = $font
    $lblBusType.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $lblBusType.AutoSize = $true
    $groupBox.Controls.Add($lblBusType)
    $currentLeft = $lblBusType.Right + $offset
    
    $lblVenPrefix = New-Object System.Windows.Forms.Label
    $lblVenPrefix.Left = $currentLeft
    $lblVenPrefix.Top = $lblPNP.Top
    $lblVenPrefix.Text = $venPrefix
    $lblVenPrefix.Font = $font
    $lblVenPrefix.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $lblVenPrefix.AutoSize = $true
    $groupBox.Controls.Add($lblVenPrefix)
    $currentLeft = $lblVenPrefix.Right + $offset
    
    $lblVendorId = New-Object System.Windows.Forms.Label
    $lblVendorId.Left = $currentLeft
    $lblVendorId.Top = $lblPNP.Top
    $lblVendorId.Text = $vendorId
    $lblVendorId.Font = $font
    $lblVendorId.ForeColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $lblVendorId.AutoSize = $true
    $groupBox.Controls.Add($lblVendorId)
    $currentLeft = $lblVendorId.Right + $offset
    
    $lblDevPrefix = New-Object System.Windows.Forms.Label
    $lblDevPrefix.Left = $currentLeft
    $lblDevPrefix.Top = $lblPNP.Top
    $lblDevPrefix.Text = $devPrefix
    $lblDevPrefix.Font = $font
    $lblDevPrefix.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $lblDevPrefix.AutoSize = $true
    $groupBox.Controls.Add($lblDevPrefix)
    $currentLeft = $lblDevPrefix.Right + $offset
    
    $lblDeviceId = New-Object System.Windows.Forms.Label
    $lblDeviceId.Left = $currentLeft
    $lblDeviceId.Top = $lblPNP.Top
    $lblDeviceId.Text = $deviceId
    $lblDeviceId.Font = $font
    $lblDeviceId.ForeColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $lblDeviceId.AutoSize = $true
    $groupBox.Controls.Add($lblDeviceId)
    $currentLeft = $lblDeviceId.Right + $offset
    
    if ($remainder) {
        $lblRemainder = New-Object System.Windows.Forms.Label
        $lblRemainder.Left = $currentLeft
        $lblRemainder.Top = $lblPNP.Top
        $lblRemainder.Text = $remainder
        $lblRemainder.Font = $font
        $lblRemainder.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
        $lblRemainder.AutoSize = $true
        $groupBox.Controls.Add($lblRemainder)
    }
}
else {
    $lblPNPValue = New-Object System.Windows.Forms.Label
    $lblPNPValue.AutoSize = $true
    $lblPNPValue.Left = $currentLeft
    $lblPNPValue.Top = $lblPNP.Top
    $lblPNPValue.Text = $pnpID
    $lblPNPValue.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $lblPNPValue.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
    $groupBox.Controls.Add($lblPNPValue)
}

$lblIRQ = New-Object System.Windows.Forms.Label
$lblIRQ.AutoSize = $true
$lblIRQ.Left = 6
$lblIRQ.Top = $lblPNP.Bottom + 8
$lblIRQ.Text = "IRQ Count: "
$lblIRQ.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
$lblIRQ.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
$groupBox.Controls.Add($lblIRQ)

$lblIRQValue = New-Object System.Windows.Forms.Label
$lblIRQValue.AutoSize = $true
$lblIRQValue.Left = $lblIRQ.Right
$lblIRQValue.Top = $lblIRQ.Top
$lblIRQValue.Text = "(Click CALCULATE IRQ COUNTS)"
$lblIRQValue.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
$lblIRQValue.ForeColor = [System.Drawing.Color]::FromArgb(219,219,219)
$groupBox.Controls.Add($lblIRQValue)

if ($device.Category -eq "USB") {
    $imodPanel = New-Object System.Windows.Forms.Panel
    $imodPanel.Left = 6
    $imodPanel.Top = $lblIRQ.Bottom + 8
    $imodPanel.Width = 600
    $imodPanel.Height = 35
$imodPanel.BackColor = [System.Drawing.Color]::Transparent
    $groupBox.Controls.Add($imodPanel)

    $lblIMOD = New-Object System.Windows.Forms.Label
    $lblIMOD.Text = "IMOD INTERVAL:"
    $lblIMOD.AutoSize = $true
    $lblIMOD.Left = 0
    $lblIMOD.Top = 8
    $lblIMOD.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 11)
    $lblIMOD.ForeColor = [System.Drawing.Color]::FromArgb(219, 219, 219)
    $imodPanel.Controls.Add($lblIMOD)

    $txtNewIMOD = New-Object System.Windows.Forms.TextBox
    $txtNewIMOD.Width = 70
    $txtNewIMOD.MaxLength = 6
    $txtNewIMOD.Left = $lblIMOD.Right + 10
    $txtNewIMOD.Top = 5
    $txtNewIMOD.Font = $lblIMOD.Font
    $txtNewIMOD.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $txtNewIMOD.ForeColor = [System.Drawing.Color]::FromArgb(219, 219, 219)
    $txtNewIMOD.BorderStyle = 'FixedSingle'
    $imodPanel.Controls.Add($txtNewIMOD)
function Update-IMOD-NsLabel {
    param($textBox, $label)

    $raw = $textBox.Text.Trim()

    if ($raw -match '^0x[0-9A-Fa-f]{1,4}$') {
        try {
            $val = [Convert]::ToUInt16($raw, 16)
            $ns = $val * 250

            if ($ns -ge 1000) {
                $usExact = $ns / 1000.0
                $label.Text = "$usExact µs"
            } else {
                $label.Text = "$ns ns"
            }
        } catch {
            $label.Text = ""
        }
    } else {
        $label.Text = ""
    }
}


$txtNewIMOD.Add_TextChanged({
    Update-IMOD-NsLabel -textBox $this -label $lblIMODns
})

$lblIMODns = New-Object System.Windows.Forms.Label
$lblIMODns.Text = ""
$lblIMODns.AutoSize = $true
$lblIMODns.Left = $txtNewIMOD.Right + 11
$lblIMODns.Top = 9
$lblIMODns.Font = $lblIMOD.Font
$lblIMODns.ForeColor = [System.Drawing.Color]::FromArgb(160, 160, 160)
$imodPanel.Controls.Add($lblIMODns)

$btnSetIMOD = New-Object System.Windows.Forms.Button
$btnSetIMOD.Text = "SET"
$btnSetIMOD.Width = 60
$btnSetIMOD.Height = 28
$btnSetIMOD.Left = $lblIMODns.Right + 333
$btnSetIMOD.Top = 5
$btnSetIMOD.Tag = $device
$btnSetIMOD.BackColor = [System.Drawing.Color]::FromArgb(0, 0, 0)
$btnSetIMOD.ForeColor = [System.Drawing.Color]::FromArgb(255, 255, 255)
$btnSetIMOD.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnSetIMOD.Font = New-Object System.Drawing.Font($fontCollection.Families[0], 13)

$imodPanel.Controls.Add($btnSetIMOD)

$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Text = "SAVE"
$btnSave.Width = 65
$btnSave.Height = 28
$btnSave.Left = $lblIMODns.Right + 402
$btnSave.Top = 5
$btnSave.BackColor = [System.Drawing.Color]::FromArgb(0,0,0)
$btnSave.ForeColor = [System.Drawing.Color]::FromArgb(255,255,255)
$btnSave.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnSave.Font = New-Object System.Drawing.Font($fontCollection.Families[0],13)
$btnSave.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
$btnSave.FlatAppearance.BorderSize = 1
$imodPanel.Controls.Add($btnSave)
$imodPanel.Width = $btnSave.Right + 15
$btnSave.Add_MouseEnter({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::White
})
$btnSave.Add_MouseLeave({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
})
$btnSave.Add_Click({
    $scriptContent = @'
$globalInterval = 0x0
$globalHCSPARAMSOffset = 0x4
$globalRTSOFF = 0x18
$userDefinedData = @{
'@
    $imodSettings = @{}
    foreach ($device in $deviceList | Where-Object { $_.Category -eq "USB" }) {
        $ctrls = $deviceControls[$device]
        $pnpId = $ctrls.PNPID
        
        if ($pnpId -match 'DEV_([0-9A-F]{4})') {
            $devId = "DEV_$($Matches[1])"
            $imodValue = $ctrls.NewIMOD.Text
            $imodSettings[$devId] = $imodValue
        }
    }
    foreach ($key in $imodSettings.Keys) {
        $scriptContent += "    `"$key`" = @{`r`n"
        $scriptContent += "        `"INTERVAL`" = $($imodSettings[$key])`r`n"
        $scriptContent += "    }`r`n"
    }
    $scriptContent += @'
}
$rwePath = "C:\Program Files (x86)\RW-Everything\Rw.exe"
function Dec-To-Hex($decimal) {
    return "0x$($decimal.ToString('X2'))"
}
function Get-Value-From-Address($address) {
    $address = Dec-To-Hex -decimal ([uint64]$address)
    $stdout = & $rwePath /Min /NoLogo /Stdout /Command="R32 $($address)" | Out-String
    $splitString = $stdout -split " "
    return [uint64]$splitString[-1]
}
function Get-Device-Addresses {
    $data = @{}
    $resources = Get-WmiObject -Class Win32_PNPAllocatedResource -ComputerName LocalHost -Namespace root\CIMV2
    foreach ($resource in $resources) {
        $deviceId = $resource.Dependent.Split("=")[1].Replace('"', '').Replace("\\", "\")
        $physicalAddress = $resource.Antecedent.Split("=")[1].Replace('"', '')
        if (-not $data.ContainsKey($deviceId) -and $deviceId -and $physicalAddress) {
            $data[$deviceId] = [uint64]$physicalAddress
        }
    }
    return $data
}
function Is-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Read-ControllerIMOD($controller, $deviceMap) {
    $deviceId = $controller.DeviceID
    if (-not $deviceMap.Contains($deviceId)) { return $null }
    $capabilityAddress = $deviceMap[$deviceId]
    $desiredInterval = $globalInterval
    $hcsparamsOffset = $globalHCSPARAMSOffset
    $rtsoff = $globalRTSOFF
    foreach ($hwid in $userDefinedData.Keys) {
        if ($deviceId -match $hwid) {
            $userDefinedController = $userDefinedData[$hwid]
            if ($userDefinedController.ContainsKey("INTERVAL"))            { $desiredInterval = $userDefinedController["INTERVAL"] }
            if ($userDefinedController.ContainsKey("HCSPARAMS_OFFSET"))    { $hcsparamsOffset = $userDefinedController["HCSPARAMS_OFFSET"] }
            if ($userDefinedController.ContainsKey("RTSOFF"))              { $rtsoff = $userDefinedController["RTSOFF"] }
        }
    }
}  
function Write-ControllerIMOD($controller, $deviceMap, $newInterval) {
    $deviceId = $controller.DeviceID
    if (-not $deviceMap.Contains($deviceId)) { return $false }
    $capabilityAddress = $deviceMap[$deviceId]
    $hcsparamsOffset = $globalHCSPARAMSOffset
    $rtsoff = $globalRTSOFF
    foreach ($hwid in $userDefinedData.Keys) {
        if ($deviceId -match $hwid) {
            $userDefinedController = $userDefinedData[$hwid]
            if ($userDefinedController.ContainsKey("HCSPARAMS_OFFSET")) { $hcsparamsOffset = $userDefinedController["HCSPARAMS_OFFSET"] }
            if ($userDefinedController.ContainsKey("RTSOFF"))           { $rtsoff          = $userDefinedController["RTSOFF"] }
        }
    }
}  
function main {
    if (-not (Is-Admin)) {
        Write-Host "error: administrator privileges required"
        return 1
    }
    if (-not (Test-Path $rwePath -PathType Leaf)) {
        Write-Host "error: $($rwePath) not exists, edit the script to change the path to Rw.exe"
        Write-Host "http://rweverything.com/download"
        return 1
    }
    Stop-Process -Name "Rw" -ErrorAction SilentlyContinue
    $deviceMap = Get-Device-Addresses
    foreach ($xhciController in Get-WmiObject Win32_USBController) {
        $isDisabled = $xhciController.ConfigManagerErrorCode -eq 22
        if ($isDisabled) { continue }
        $deviceId = $xhciController.DeviceID
        Write-Host "$($xhciController.Caption) - $($deviceId)"
        if (-not $deviceMap.Contains($deviceId)) {
            Write-Host "error: could not obtain base address`n"
            continue
        }
        $desiredInterval = $globalInterval
        $hcsparamsOffset = $globalHCSPARAMSOffset
        $rtsoff = $globalRTSOFF
        foreach ($hwid in $userDefinedData.Keys) {
            if ($deviceId -match $hwid) {
                $userDefinedController = $userDefinedData[$hwid]
                if ($userDefinedController.ContainsKey("INTERVAL")) {
                    $desiredInterval = $userDefinedController["INTERVAL"]
                }
                if ($userDefinedController.ContainsKey("HCSPARAPS_OFFSET")) {
                    $hcsparamsOffset = $userDefinedController["HCSPARAPS_OFFSET"]
                }
                if ($userDefinedController.ContainsKey("RTSOFF")) {
                    $rtsoff = $userDefinedController["RTSOFF"]
                }
            }
        }
        $capabilityAddress = $deviceMap[$deviceId]
        $HCSPARAMSValue = Get-Value-From-Address -address ($capabilityAddress + $hcsparamsOffset)
        $HCSPARAMSBitmask = [Convert]::ToString($HCSPARAMSValue, 2)
        $maxIntrs = [Convert]::ToInt32($HCSPARAMSBitmask.Substring($HCSPARAMSBitmask.Length - 16, 8), 2)
        $RTSOFFValue = Get-Value-From-Address -address ($capabilityAddress + $rtsoff)
        $runtimeAddress = $capabilityAddress + $RTSOFFValue
        for ($i = 0; $i -lt $maxIntrs; $i++) {
            $interrupterAddress = Dec-To-Hex -decimal ([uint64]($runtimeAddress + 0x24 + (0x20 * $i)))
            & $rwePath /Min /NoLogo /Stdout /Command="W32 $($interrupterAddress) $($desiredInterval)" | Write-Host
        }
        Write-Host
    }
    return 0
}
$_exitCode = main
exit $_exitCode
'@
    $startupPath = [Environment]::GetFolderPath('Startup')
    $scriptPath = Join-Path $startupPath "ApplyIMOD.ps1"
    Set-Content -Path $scriptPath -Value $scriptContent -Encoding UTF8
    [System.Windows.Forms.MessageBox]::Show(
        "IMOD script saved to:`n$scriptPath`n`nIt will run at every startup.",
        "IMOD Settings Saved",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
})

$btnSetIMOD.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255, 100, 45)
$btnSetIMOD.FlatAppearance.BorderSize = 1

$btnSetIMOD.Add_MouseEnter({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::White
})

$btnSetIMOD.Add_MouseLeave({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255, 100, 45)
})

    $deviceControls[$device] = @{
        CurrentIMOD = $txtCurrentIMOD
        NewIMOD     = $txtNewIMOD
    }

    function Read-AndDisplayIMOD {
        $ctrls = $deviceControls[$device]
        $instanceId = Split-Path -Leaf $device.RegistryPath

        $controllers = Get-WmiObject Win32_USBController | Where-Object {
            $_.ConfigManagerErrorCode -ne 22
        }

        $matchedController = $null
        foreach ($controller in $controllers) {
            $controllerId = $controller.DeviceID -replace '\\\\', '\\'
            if ($controllerId -match [regex]::Escape($instanceId)) {
                $matchedController = $controller
                break
            }
        }

        if (-not $matchedController) {
            $ctrls.CurrentIMOD.Text = "Error: No matching controller"
            return
        }

        $imodValues = Read-ControllerIMOD $matchedController $globalDeviceAddressMap

        if ($imodValues) {
            $unique = $imodValues | Select-Object -Unique
            if ($unique.Count -eq 1) {
                $hexVal = "0x$($unique[0].ToString('X4'))"
                $ctrls.CurrentIMOD.Text = $hexVal
$ctrls.NewIMOD.Text = $hexVal
Update-IMOD-NsLabel -textBox $ctrls.NewIMOD -label $lblIMODns

            } else {
                $ctrls.CurrentIMOD.Text = "Multiple values"
            }
        } else {
            $ctrls.CurrentIMOD.Text = "Error reading"
        }
    }

    Read-AndDisplayIMOD

$btnSetIMOD.Add_Click({
    function Update-IMOD-NsLabel {
        param($textBox, $label)

        $raw = $textBox.Text.Trim()

        if ($raw -match '^0x[0-9A-Fa-f]{1,4}$') {
            try {
                $val = [Convert]::ToUInt16($raw, 16)
                $ns = $val * 250

                if ($ns -ge 1000) {
                    $usExact = $ns / 1000.0
                    $label.Text = "$usExact µs"
                } else {
                    $label.Text = "$ns ns"
                }
            } catch {
                $label.Text = ""
            }
        } else {
            $label.Text = ""
        }
    }

    $device = $this.Tag
    $ctrls = $deviceControls[$device]
    $newIMOD = $ctrls.NewIMOD.Text
    
    Write-Host "CurrentIMOD type: $($ctrls.CurrentIMOD.GetType().FullName)"
    Write-Host "NewIMOD type: $($ctrls.NewIMOD.GetType().FullName)"
    
    if (-not ($newIMOD -match '^0x[0-9A-Fa-f]{1,4}$')) {
        [System.Windows.Forms.MessageBox]::Show("Invalid IMOD format. Use hex format (e.g., 0x4E20)", "Error", "OK", "Error")
        return
    }
    
    $instanceId = Split-Path -Leaf $device.RegistryPath
    
    $controllers = Get-WmiObject Win32_USBController | Where-Object {
        $_.ConfigManagerErrorCode -ne 22
    }
    
    $matchedController = $null
    foreach ($controller in $controllers) {
        $controllerId = $controller.DeviceID -replace '\\\\', '\\' 
        if ($controllerId -match [regex]::Escape($instanceId)) {
            $matchedController = $controller
            break
        }
    }
    
    if (-not $matchedController) {
        [System.Windows.Forms.MessageBox]::Show("No matching controller found", "Error", "OK", "Error")
        return
    }
    
    $imodValue = [Convert]::ToUInt16($newIMOD, 16)  
    $result = Write-ControllerIMOD $matchedController $globalDeviceAddressMap $imodValue
    
    if ($result) {
        if ($ctrls.CurrentIMOD) {
            $objectType = $ctrls.CurrentIMOD.GetType().Name
            Write-Host "Attempting to update CurrentIMOD of type: $objectType"
            
            try {
                if ($objectType -eq "TextBox") {
                    $ctrls.CurrentIMOD.Text = "0x$($imodValue.ToString('X4'))"
                } elseif ($objectType -eq "Label") {
                    $ctrls.CurrentIMOD.Text = "0x$($imodValue.ToString('X4'))"
                } else {
                    if ($ctrls.CurrentIMOD | Get-Member -Name "Text") {
                        $ctrls.CurrentIMOD.Text = "0x$($imodValue.ToString('X4'))"
                    } else {
                        Write-Host "CurrentIMOD does not have Text property"
                    }
                }
            } catch {
                Write-Host "Error updating CurrentIMOD: $($_.Exception.Message)"
            }
        }
        
        if ($ctrls.NewIMOD -and $ctrls.IMODNsLabel) {
            try {
                Update-IMOD-NsLabel -textBox $ctrls.NewIMOD -label $ctrls.IMODNsLabel
            } catch {
                Write-Host "Error updating IMOD ns label: $($_.Exception.Message)"
            }
        }
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("Failed to apply IMOD settings", "Error", "OK", "Error")
    }
})

$btnSetIMOD.Add_Click({
    function Update-IMOD-NsLabel {
        param($textBox, $label)

        $raw = $textBox.Text.Trim()

        if ($raw -match '^0x[0-9A-Fa-f]{1,4}$') {
            try {
                $val = [Convert]::ToUInt16($raw, 16)
                $ns = $val * 250

                if ($ns -ge 1000) {
                    $usExact = $ns / 1000.0
                    $label.Text = "$usExact µs"
                } else {
                    $label.Text = "$ns ns"
                }
            } catch {
                $label.Text = ""
            }
        } else {
            $label.Text = ""
        }
    }

    $device = $this.Tag
    $ctrls = $deviceControls[$device]
    $newIMOD = $ctrls.NewIMOD.Text
    
    if (-not ($newIMOD -match '^0x[0-9A-Fa-f]{1,4}$')) {
        [System.Windows.Forms.MessageBox]::Show("Invalid IMOD format. Use hex format (e.g., 0x4E20)", "Error", "OK", "Error")
        return
    }
    
    $instanceId = Split-Path -Leaf $device.RegistryPath
    
    $controllers = Get-WmiObject Win32_USBController | Where-Object {
        $_.ConfigManagerErrorCode -ne 22
    }
    
    $matchedController = $null
    foreach ($controller in $controllers) {
        $controllerId = $controller.DeviceID -replace '\\\\', '\\'
        if ($controllerId -match [regex]::Escape($instanceId)) {
            $matchedController = $controller
            break
        }
    }
    
    if (-not $matchedController) {
        [System.Windows.Forms.MessageBox]::Show("No matching controller found", "Error", "OK", "Error")
        return
    }
    
    $imodValue = [Convert]::ToUInt16($newIMOD, 16)
    $result = Write-ControllerIMOD $matchedController $globalDeviceAddressMap $imodValue
    
    if ($result) {
        $imodPanel = $this.Parent
        $currentIMODTextBox = $null
        
        foreach ($control in $imodPanel.Controls) {
            if ($control -is [System.Windows.Forms.TextBox] -and $control.Name -like "*Current*") {
                $currentIMODTextBox = $control
                break
            }
        }
        
        if ($currentIMODTextBox) {
            $currentIMODTextBox.Text = "0x$($imodValue.ToString('X4'))"
        }
        
        $nsLabel = $null
        foreach ($control in $imodPanel.Controls) {
            if ($control -is [System.Windows.Forms.Label] -and $control.ForeColor.Name -eq "ffa0a0a0") {
                $nsLabel = $control
                break
            }
        }
        
        if ($ctrls.NewIMOD -and $nsLabel) {
            Update-IMOD-NsLabel -textBox $ctrls.NewIMOD -label $nsLabel
        }
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("Failed to apply IMOD settings", "Error", "OK", "Error")
    }
})

    $deviceControls[$device] = @{
        CheckBoxes    = $checkboxes;
        MaskLabel     = $lblMask;
        MaskValue     = $lblMaskValue;
        InitialValue  = $initialValue;
        MSICombo      = $cboMSI;
        MsgLimitBox   = $msgLimitBox;
        PriorityCombo = $cboPriority;
        PNPID         = $pnpId;
        IRQLabel      = $lblIRQ;
        IRQValueLabel = $lblIRQValue;
        CurrentIMOD   = $txtCurrentIMOD;
        NewIMOD       = $txtNewIMOD
        PolicyCombo   = $cboPolicy
        NumQueues     = $nudNumQueues
    }
    
    $btnReadIMOD.Add_Click({
        $device = $this.Tag
        $ctrls = $deviceControls[$device]
        
        $instanceId = Split-Path -Leaf $device.RegistryPath
        
        $controllers = Get-WmiObject Win32_USBController | Where-Object {
            $_.ConfigManagerErrorCode -ne 22
        }
        
        $matchedController = $null
        foreach ($controller in $controllers) {
            $controllerId = $controller.DeviceID -replace '\\\\', '\\'  
            if ($controllerId -match [regex]::Escape($instanceId)) {
                $matchedController = $controller
                break
            }
        }
        
        if (-not $matchedController) {
            $ctrls.CurrentIMOD.Text = "Error: No matching controller"
            return
        }
        
        $imodValues = Read-ControllerIMOD $matchedController $globalDeviceAddressMap
        
    if ($imodValues) {
        $unique = $imodValues | Select-Object -Unique
        if ($unique.Count -eq 1) {
            $ctrls.CurrentIMOD.Text = "0x$($unique[0].ToString('X4'))"
        } else {
            $ctrls.CurrentIMOD.Text = "Multiple values"
        }
    }
    else {
        $ctrls.CurrentIMOD.Text = "Error reading"
    }
})
    
    $btnSetIMOD.Add_Click({
        $device = $this.Tag
        $ctrls = $deviceControls[$device]
        $newIMOD = $ctrls.NewIMOD.Text
        
        if (-not ($newIMOD -match '^0x[0-9A-Fa-f]{1,4}$')) {
            [System.Windows.Forms.MessageBox]::Show("Invalid IMOD format. Use hex format (e.g., 0x4E20)", "Error", "OK", "Error")
            return
        }
        
        $instanceId = Split-Path -Leaf $device.RegistryPath
        
        $controllers = Get-WmiObject Win32_USBController | Where-Object {
            $_.ConfigManagerErrorCode -ne 22
        }
        
        $matchedController = $null
        foreach ($controller in $controllers) {
            $controllerId = $controller.DeviceID -replace '\\\\', '\\'  
            if ($controllerId -match [regex]::Escape($instanceId)) {
                $matchedController = $controller
                break
            }
        }
        
        if (-not $matchedController) {
            [System.Windows.Forms.MessageBox]::Show("No matching controller found", "Error", "OK", "Error")
            return
        }
        
    $imodValue = [Convert]::ToUInt16($newIMOD, 16)  
    $result = Write-ControllerIMOD $matchedController $globalDeviceAddressMap $imodValue
    
    if ($result) {
        $ctrls.CurrentIMOD.Text = "0x$($imodValue.ToString('X4'))"
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("Failed to apply IMOD settings", "Error", "OK", "Error")
    }
})
}
else {
    $deviceControls[$device] = @{
        CheckBoxes    = $checkboxes;
        MaskLabel     = $lblMask;
        MaskValue     = $lblMaskValue;
        InitialValue  = $initialValue;
        MSICombo      = $cboMSI;
        MsgLimitBox   = $msgLimitBox;
        PriorityCombo = $cboPriority;
        PNPID         = $pnpId;
        IRQLabel      = $lblIRQ;
        IRQValueLabel = $lblIRQValue
        PolicyCombo   = $cboPolicy
        NumQueues     = $nudNumQueues
    }
}

    foreach ($chk in $checkboxes) {
        $chk.Add_CheckedChanged({
            param($sender, $e)
            if ($script:NDISUpdating) { return } 

            $parentGroup = $sender.Parent.Parent
            $dev = $parentGroup.Tag
            $ctrls = $deviceControls[$dev]

            if ($dev.Category -eq "Network" -and $dev.Role -eq "NDIS") {

                if ($sender.Checked) {
                    $baseCore = [int]$sender.Tag
                    $numQueues = 1
                    try { $numQueues = [int]$ctrls.NumQueues.Value } catch { $numQueues = 1 }
                    if ($numQueues -lt 1) { $numQueues = 1 }

                    $logicalCount = [Environment]::ProcessorCount
                    $selectedSet = @()
                    for ($i=0; $i -lt $numQueues; $i++) {
                        $c = ($baseCore + $i) % $logicalCount
                        $selectedSet += $c
                    }

                    $script:NDISUpdating = $true
                    foreach ($other in $ctrls.CheckBoxes) {
                        $core = [int]$other.Tag
                        if ($selectedSet -contains $core) {
                            $other.Checked = $true
                            $other.AutoCheck = $false
                        } else {
                            $other.Checked = $false
                            $other.AutoCheck = $true
                        }
                    }
                    $script:NDISUpdating = $false

                    $maskInt = 0
                    foreach ($c in $selectedSet) { $maskInt = $maskInt -bor (1 -shl $c) }
                    $ctrls.MaskValue.Text = "0x" + ([Convert]::ToString($maskInt,16)).ToUpper()
                }
                else {
                    $script:NDISUpdating = $true
                    foreach ($other in $ctrls.CheckBoxes) {
                        $other.Checked = $false
                        $other.AutoCheck = $true
                    }
                    $script:NDISUpdating = $false
                    $ctrls.MaskValue.Text = "0x0"
                }
            } else {
                $newHex = Calculate-AffinityHex $ctrls.CheckBoxes
                if ($newHex -eq "0x0") {
                    $ctrls.MaskLabel.Text = "Affinity Mask: "
                    $ctrls.MaskValue.Text = "0x0"
                } else {
                    $ctrls.MaskLabel.Text = "Affinity Mask: "
                    $ctrls.MaskValue.Text = $newHex
                }
            }
        })
    }
    $panel.Controls.Add($groupBox)
}

$btnSaveIMOD.Add_MouseEnter({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(234,234,234)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})
$btnSaveIMOD.Add_MouseLeave({
    $this.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(255,100,45)
    $this.FlatAppearance.BorderSize = 1
    $this.Refresh()
})
$btnSaveIMOD.Add_Click({
    $scriptContent = @'
$globalInterval = 0x0
$globalHCSPARAMSOffset = 0x4
$globalRTSOFF = 0x18
$userDefinedData = @{
'@
    $imodSettings = @{}
    foreach ($device in $deviceList | Where-Object { $_.Category -eq "USB" }) {
        $ctrls = $deviceControls[$device]
        $pnpId = $ctrls.PNPID
        
        if ($pnpId -match 'DEV_([0-9A-F]{4})') {
            $devId = "DEV_$($Matches[1])"
            $imodValue = $ctrls.NewIMOD.Text
            $imodSettings[$devId] = $imodValue
        }
    }
    foreach ($key in $imodSettings.Keys) {
        $scriptContent += "    `"$key`" = @{`r`n"
        $scriptContent += "        `"INTERVAL`" = $($imodSettings[$key])`r`n"
        $scriptContent += "    }`r`n"
    }
    $scriptContent += @'
}
$rwePath = "C:\Program Files (x86)\RW-Everything\Rw.exe"
function Dec-To-Hex($decimal) {
    return "0x$($decimal.ToString('X2'))"
}
function Get-Value-From-Address($address) {
    $address = Dec-To-Hex -decimal ([uint64]$address)
    $stdout = & $rwePath /Min /NoLogo /Stdout /Command="R32 $($address)" | Out-String
    $splitString = $stdout -split " "
    return [uint64]$splitString[-1]
}
function Get-Device-Addresses {
    $data = @{}
    $resources = Get-WmiObject -Class Win32_PNPAllocatedResource -ComputerName LocalHost -Namespace root\CIMV2
    foreach ($resource in $resources) {
        $deviceId = $resource.Dependent.Split("=")[1].Replace('"', '').Replace("\\", "\")
        $physicalAddress = $resource.Antecedent.Split("=")[1].Replace('"', '')
        if (-not $data.ContainsKey($deviceId) -and $deviceId -and $physicalAddress) {
            $data[$deviceId] = [uint64]$physicalAddress
        }
    }
    return $data
}
function Is-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Read-ControllerIMOD($controller, $deviceMap) {
    $deviceId = $controller.DeviceID
    if (-not $deviceMap.Contains($deviceId)) { return $null }
    $capabilityAddress = $deviceMap[$deviceId]
    $desiredInterval = $globalInterval
    $hcsparamsOffset = $globalHCSPARAMSOffset
    $rtsoff = $globalRTSOFF
    foreach ($hwid in $userDefinedData.Keys) {
        if ($deviceId -match $hwid) {
            $userDefinedController = $userDefinedData[$hwid]
            if ($userDefinedController.ContainsKey("INTERVAL"))            { $desiredInterval = $userDefinedController["INTERVAL"] }
            if ($userDefinedController.ContainsKey("HCSPARAMS_OFFSET"))    { $hcsparamsOffset = $userDefinedController["HCSPARAMS_OFFSET"] }
            if ($userDefinedController.ContainsKey("RTSOFF"))              { $rtsoff = $userDefinedController["RTSOFF"] }
        }
    }
}  
function Write-ControllerIMOD($controller, $deviceMap, $newInterval) {
    $deviceId = $controller.DeviceID
    if (-not $deviceMap.Contains($deviceId)) { return $false }
    $capabilityAddress = $deviceMap[$deviceId]
    $hcsparamsOffset = $globalHCSPARAMSOffset
    $rtsoff = $globalRTSOFF
    foreach ($hwid in $userDefinedData.Keys) {
        if ($deviceId -match $hwid) {
            $userDefinedController = $userDefinedData[$hwid]
            if ($userDefinedController.ContainsKey("HCSPARAMS_OFFSET")) { $hcsparamsOffset = $userDefinedController["HCSPARAMS_OFFSET"] }
            if ($userDefinedController.ContainsKey("RTSOFF"))           { $rtsoff          = $userDefinedController["RTSOFF"] }
        }
    }
}  
function main {
    if (-not (Is-Admin)) {
        Write-Host "error: administrator privileges required"
        return 1
    }
    if (-not (Test-Path $rwePath -PathType Leaf)) {
        Write-Host "error: $($rwePath) not exists, edit the script to change the path to Rw.exe"
        Write-Host "http://rweverything.com/download"
        return 1
    }
    Stop-Process -Name "Rw" -ErrorAction SilentlyContinue
    $deviceMap = Get-Device-Addresses
    foreach ($xhciController in Get-WmiObject Win32_USBController) {
        $isDisabled = $xhciController.ConfigManagerErrorCode -eq 22
        if ($isDisabled) { continue }
        $deviceId = $xhciController.DeviceID
        Write-Host "$($xhciController.Caption) - $($deviceId)"
        if (-not $deviceMap.Contains($deviceId)) {
            Write-Host "error: could not obtain base address`n"
            continue
        }
        $desiredInterval = $globalInterval
        $hcsparamsOffset = $globalHCSPARAMSOffset
        $rtsoff = $globalRTSOFF
        foreach ($hwid in $userDefinedData.Keys) {
            if ($deviceId -match $hwid) {
                $userDefinedController = $userDefinedData[$hwid]
                if ($userDefinedController.ContainsKey("INTERVAL")) {
                    $desiredInterval = $userDefinedController["INTERVAL"]
                }
                if ($userDefinedController.ContainsKey("HCSPARAPS_OFFSET")) {
                    $hcsparamsOffset = $userDefinedController["HCSPARAPS_OFFSET"]
                }
                if ($userDefinedController.ContainsKey("RTSOFF")) {
                    $rtsoff = $userDefinedController["RTSOFF"]
                }
            }
        }
        $capabilityAddress = $deviceMap[$deviceId]
        $HCSPARAMSValue = Get-Value-From-Address -address ($capabilityAddress + $hcsparamsOffset)
        $HCSPARAMSBitmask = [Convert]::ToString($HCSPARAMSValue, 2)
        $maxIntrs = [Convert]::ToInt32($HCSPARAMSBitmask.Substring($HCSPARAMSBitmask.Length - 16, 8), 2)
        $RTSOFFValue = Get-Value-From-Address -address ($capabilityAddress + $rtsoff)
        $runtimeAddress = $capabilityAddress + $RTSOFFValue
        for ($i = 0; $i -lt $maxIntrs; $i++) {
            $interrupterAddress = Dec-To-Hex -decimal ([uint64]($runtimeAddress + 0x24 + (0x20 * $i)))
            & $rwePath /Min /NoLogo /Stdout /Command="W32 $($interrupterAddress) $($desiredInterval)" | Write-Host
        }
        Write-Host
    }
    return 0
}
$_exitCode = main
exit $_exitCode
'@
    $startupPath = [Environment]::GetFolderPath('Startup')
    $scriptPath = Join-Path $startupPath "ApplyIMOD.ps1"
    Set-Content -Path $scriptPath -Value $scriptContent -Encoding UTF8
    [System.Windows.Forms.MessageBox]::Show(
        "IMOD script saved to:`n$scriptPath`n`nIt will run at every startup.",
        "IMOD Settings Saved",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
})

$form.SuspendLayout()
$panel.SuspendLayout()

$bindingFlags = [System.Reflection.BindingFlags] "NonPublic, Instance"
$form.GetType().GetProperty('DoubleBuffered', $bindingFlags).SetValue($form, $true, $null)
$panel.GetType().GetProperty('DoubleBuffered', $bindingFlags).SetValue($panel, $true, $null)

$topPos = $btnAutoOpt.Bottom + 26
foreach ($dev in $deviceList) {
    Create-DeviceGroupBox $dev $topPos
    $boxHeight = if ($dev.Category -eq "USB") { 395 } else { 340 }
    $topPos += $boxHeight + $deviceBoxSpacing 
}

$topPos = Create-ReservedCpuSetsUI -topPos $topPos

$panel.ResumeLayout()
$form.ResumeLayout()

$btnApply.Add_Click({
    $occupiedCores = @()
    $weakOccupiedCores = @()          
    $logicalCount = [Environment]::ProcessorCount

    foreach ($device in $deviceList) {
        $normRoles = @()
        foreach ($rr in $device.Roles) {
            if (-not $rr) { continue }
            $parts = $rr -split '[\/,;]+' 
            foreach ($pp in $parts) {
                $tokRaw = $pp.Trim()
                if ($tokRaw -eq '') { continue }
                $l = $tokRaw.ToLower()
                if ($l -match 'mic|microphone')                      { $tok = 'Audio' }
                elseif ($l -match 'headphone|headphones|headset')   { $tok = 'Audio' }
                elseif ($l -match 'earphone|earphones|iem')         { $tok = 'Audio' }
                elseif ($l -match 'speaker|speakers')               { $tok = 'Audio' }
                elseif ($l -match '^audio$')                        { $tok = 'Audio' }
                elseif ($l -match 'keyboard|kbd')                   { $tok = 'Keyboard' }
                elseif ($l -match 'mouse|ms')                       { $tok = 'Mouse' }
                else                                                 { $tok = $tokRaw }
                if (-not ($normRoles -contains $tok)) { $normRoles += $tok }
            }
        }
        $ctrls = $deviceControls[$device]

        if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") {
            $selectedBase = $null
            foreach ($chk in $ctrls.CheckBoxes) { if ($chk.Checked) { $selectedBase = [int]$chk.Tag; break } }
            if ($selectedBase -eq $null) { $assignedCores = @(); $valueToSet = "" }
            else {
                $numQueuesToWrite = 1
                try { $numQueuesToWrite = [int]$ctrls.NumQueues.Value } catch { $numQueuesToWrite = 1 }
                if ($numQueuesToWrite -lt 1) { $numQueuesToWrite = 1 }

                $valueToSet = "$selectedBase"
                try {
                    Set-ItemProperty -Path $device.RegistryPath -Name "*RssBaseProcNumber" -Value $valueToSet -Type String -ErrorAction Stop
                } catch { }

                try {
                    Set-ItemProperty -Path $device.RegistryPath -Name "*NumRssQueues" -Value ("$numQueuesToWrite") -Type String -ErrorAction Stop
                } catch { }

                $assignedCores = @()
                $logicalCount = [Environment]::ProcessorCount
                for ($i=0; $i -lt $numQueuesToWrite; $i++) {
                    $c = ($selectedBase + $i) % $logicalCount
                    $assignedCores += $c
                }
            }
        }
        elseif ($device.Category -eq "Network" -and $device.Role -eq "NetAdapterCx") {
            $targetRegistryPath = Get-NetworkAdapterAffinityRegistryPath $device
            $computed = Calculate-AffinityHex $ctrls.CheckBoxes
            if ($computed -eq "0x0") { }
            $result = Set-DeviceAffinity $targetRegistryPath $computed
            if ($result) { }
            $maskText = $ctrls.MaskValue.Text -replace "0x",""
            $assignedCores = @()
            if ($maskText -and ([int]::TryParse($maskText, [System.Globalization.NumberStyles]::HexNumber, $null, [ref]$null))) {
                $maskInt = [Convert]::ToInt64($maskText, 16)
                $binary = [Convert]::ToString($maskInt, 2).PadLeft($logicalCount, '0')
                for ($i = 0; $i -lt $binary.Length; $i++) {
                    if ($binary[$i] -eq '1') {
                        $assignedCores += ($binary.Length - $i - 1)
                    }
                }
            }
        }
        else {
            $computed = Calculate-AffinityHex $ctrls.CheckBoxes
            if ($computed -eq "0x0") { }
            $result = Set-DeviceAffinity $device.RegistryPath $computed
            if ($result) { }
            $maskText = $ctrls.MaskValue.Text -replace "0x",""
            $assignedCores = @()
            if ($maskText -and ([int]::TryParse($maskText, [System.Globalization.NumberStyles]::HexNumber, $null, [ref]$null))) {
                $maskInt = [Convert]::ToInt64($maskText, 16)
                $binary = [Convert]::ToString($maskInt, 2).PadLeft($logicalCount, '0')
                for ($i = 0; $i -lt $binary.Length; $i++) {
                    if ($binary[$i] -eq '1') {
                        $assignedCores += ($binary.Length - $i - 1)
                    }
                }
            }
        }

        if ($device.Category -eq "Network") {
            $targetRegistryPath = Get-NetworkAdapterMSIRegistryPath $device
        } else {
            $targetRegistryPath = $device.RegistryPath
        }
        $msiEnabled = 0
        if ($ctrls.MSICombo.SelectedItem -eq "Enabled") { $msiEnabled = 1 } else { $msiEnabled = 0 }
        $msgLimit = $ctrls.MsgLimitBox.Text
        if ($msgLimit -eq "Unlimited" -or $msgLimit -eq "0") {
            $msgLimit = ""
        }
        if ($msgLimit -eq "") { $displayMsgLimit = "Unlimited" } else { $displayMsgLimit = $msgLimit }
        $msiResult = Set-DeviceMSI $targetRegistryPath $msiEnabled $msgLimit
        if (-not $msiResult) { }
        $priorityVal = 2
        switch ($ctrls.PriorityCombo.SelectedItem) {
            "Low" { $priorityVal = 1 }
            "Normal" { $priorityVal = 2 }
            "High" { $priorityVal = 3 }
        }
        $priResult = Set-DevicePriority $targetRegistryPath $priorityVal
        if (-not $priResult) { }

        if (-not ($device.Category -eq "Network" -and $device.Role -eq "NDIS")) {
            $policyValue = $ctrls.PolicyCombo.SelectedIndex
            $policyResult = Set-DevicePolicy $device.RegistryPath $policyValue
        }

        $shouldConsiderCores = $false
        if ($device.Category -eq "Network" -and $device.Role -eq "NDIS") {
            $shouldConsiderCores = $true
        } else {
            if ($deviceControls[$device].ContainsKey('PolicyCombo')) {
                $policyValue = $deviceControls[$device].PolicyCombo.SelectedIndex
                if ($policyValue -eq 4) {
                    $shouldConsiderCores = $true
                }
            }
        }

        if ($shouldConsiderCores) {
            if (-not $assignedCores -or $assignedCores.Count -eq 0) {
                $ctrls = $deviceControls[$device]
                $assignedCores = @()
                $maskText = ($ctrls.MaskValue.Text -replace "0x","").Trim()
                if ($maskText -and ([int]::TryParse($maskText, [System.Globalization.NumberStyles]::HexNumber, $null, [ref]$null))) {
                    $maskInt = [Convert]::ToInt64($maskText, 16)
                    for ($i = 0; $i -lt [Environment]::ProcessorCount; $i++) {
                        if (($maskInt -band (1 -shl $i)) -ne 0) { $assignedCores += $i }
                    }
                } else {
                    foreach ($chk in $ctrls.CheckBoxes) {
                        if ($chk.Checked) { $assignedCores += [int]$chk.Tag }
                    }
                    $assignedCores = $assignedCores | Select-Object -Unique
                }
            }
            if ($device.Category -eq "PCI" -and $device.Role -eq "GPU") {
                $occupiedCores += $assignedCores
            }
            elseif ($device.Category -eq "USB" -and ($normRoles -contains "Mouse" -or $normRoles -contains "Controller")) {
                $occupiedCores += $assignedCores
            }
            elseif ($device.Category -eq "USB" -and ($normRoles -contains "Audio") -and ($normRoles.Count -eq 1)) {
                $weakOccupiedCores += $assignedCores
            }
            elseif ($device.Category -eq "PCI" -and $device.Role -eq "Audio") {
                $weakOccupiedCores += $assignedCores
            }
            elseif ($device.Category -eq "Network") {
                $weakOccupiedCores += $assignedCores
            }
            elseif ($normRoles -contains "Keyboard" -and $normRoles -contains "Audio") {
                $weakOccupiedCores += $assignedCores
            }
            elseif ($device.Category -eq "USB" -and ($normRoles -contains "Keyboard") -and ($normRoles.Count -eq 1)) {
                $weakOccupiedCores += $assignedCores
            }
            else {
                if ($assignedCores) {
                    $weakOccupiedCores += $assignedCores
                }
            }
        }
    }

    $occupiedCores = $occupiedCores | Select-Object -Unique | Sort-Object
    $occupiedCoresString = $occupiedCores -join ','

    $weakOccupiedCores = $weakOccupiedCores | Select-Object -Unique | Sort-Object
    $weakOccupiedCoresString = $weakOccupiedCores -join ','

    $mouseCore = $null 
    foreach ($dev in $deviceList) {
        if ($dev.Category -eq "USB" -and $dev.Roles -contains "Mouse") {
            $ctrls = $deviceControls[$dev]
            $maskValue = $ctrls.MaskValue.Text -replace "0x",""

            if ([int]::TryParse($maskValue, [System.Globalization.NumberStyles]::HexNumber, $null, [ref]$null)) {
                $maskInt = [Convert]::ToInt64($maskValue, 16)
                if ($maskInt -gt 0) {
                    for ($i = 0; $i -lt [Environment]::ProcessorCount; $i++) {
                        if (($maskInt -band (1 -shl $i)) -ne 0) {
                            $mouseCore = $i
                            break
                        }
                    }
                }
            }
            break
        }
    }

    Refresh-DeviceUI

    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptDir = if ($scriptPath) { Split-Path -Parent $scriptPath } else { Get-Location }
    $gamesCfgPath = Join-Path $scriptDir "games_priorities.cfg"
    $systemCfgPath = Join-Path $scriptDir "system_priorities.cfg"

    function Update-ConfigFile {
        param (
            [string]$filePath,
            [string]$coresString,
            [string]$weakCoresString = "",   
            [int]   $mouseCore = -1,
            [int]   $dwmCore   = -1
        )
        $content = if (Test-Path $filePath) { 
            [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::UTF8) 
        } else { 
            "" 
        }

        if ($dwmCore -ge 0 -and $filePath.EndsWith("system_priorities.cfg")) {
            $pattern = 'threaddesc=DWM Kernel Sensor Thread, \(.*?\)'
            $replacement = "threaddesc=DWM Kernel Sensor Thread, ($dwmCore)"
            $content = $content -replace $pattern, $replacement
        }

        if ($mouseCore -ge 0 -and $filePath.EndsWith("system_priorities.cfg")) {
            $pattern = 'threaddesc=DWM Master Input Thread, \(.*?\)'
            $replacement = "threaddesc=DWM Master Input Thread, ($mouseCore)"
            $content = $content -replace $pattern, $replacement
        }

        $content = $content -replace '(?m)^occupied_affinity_cores=.*$', "occupied_affinity_cores=$coresString"
        $content = $content -replace '(?m)^occupied_ideal_processor_cores=.*$', "occupied_ideal_processor_cores=$coresString"

        $content = $content -replace '(?m)^occupied_weak_affinity_cores=.*$', "occupied_weak_affinity_cores=$weakCoresString"
        $content = $content -replace '(?m)^occupied_weak_ideal_processor_cores=.*$', "occupied_weak_ideal_processor_cores=$weakCoresString"

        if (-not ($content -match "occupied_affinity_cores=")) {
            $content += "`r`noccupied_affinity_cores=$coresString"
        }
        if (-not ($content -match "occupied_ideal_processor_cores=")) {
            $content += "`r`noccupied_ideal_processor_cores=$coresString"
        }

        if (-not ($content -match "occupied_weak_affinity_cores=")) {
            $content += "`r`noccupied_weak_affinity_cores=$weakCoresString"
        }
        if (-not ($content -match "occupied_weak_ideal_processor_cores=")) {
            $content += "`r`noccupied_weak_ideal_processor_cores=$weakCoresString"
        }

        [System.IO.File]::WriteAllText($filePath, $content.Trim(), [System.Text.UTF8Encoding]::new($false))
    }

    Update-ConfigFile -filePath $gamesCfgPath -coresString $occupiedCoresString -weakCoresString $weakOccupiedCoresString
    Update-ConfigFile -filePath $systemCfgPath -coresString $occupiedCoresString -weakCoresString $weakOccupiedCoresString -mouseCore $mouseCore -dwmCore $dwmCore

    [System.Windows.Forms.MessageBox]::Show("Settings applied. A system restart required.", "Done")
})

function Get-AutoOptRoles($device) {

    function Normalize-RawRoles($rawRoles) {
        $norm = @()
        foreach ($r in $rawRoles) {
            if (-not $r) { continue }
            $parts = $r -split '[\/,;]+' 
            foreach ($p in $parts) {
                $t = $p.Trim()
                if ($t -eq '') { continue }
                $lt = $t.ToLower()
                if ($lt -match 'mic|microphone')                      { $tok = 'Audio' }
                elseif ($lt -match 'headphone|headphones|headset')   { $tok = 'Audio' }
                elseif ($lt -match 'earphone|earphones|iem')         { $tok = 'Audio' }
                elseif ($lt -match 'speaker|speakers')               { $tok = 'Audio' }
                elseif ($lt -match '^audio$')                        { $tok = 'Audio' }
                elseif ($lt -match 'keyboard|kbd')                   { $tok = 'Keyboard' }
                elseif ($lt -match 'mouse|ms')                       { $tok = 'Mouse' }
                else                                                 { $tok = $t }  
                if (-not ($norm -contains $tok)) { $norm += $tok }
            }
        }
        return $norm
    }

    if ($device.Category -eq 'USB') {
        $normRoles = Normalize-RawRoles $device.Roles
        $nonAudio = $normRoles | Where-Object { $_ -ne 'Audio' }
        if (-not $nonAudio -and $normRoles.Count -gt 0) { return @('Audio') }

        $result = @()
        if ($normRoles -contains 'Audio') { $result += 'Audio' }
        foreach ($t in $normRoles) { if ($t -ne 'Audio' -and -not ($result -contains $t)) { $result += $t } }
        return $result
    }

    return Normalize-RawRoles $device.Roles
}

function Get-PCoreIndices {
    $pCoreIndices = @()
    $logicalCount = [Environment]::ProcessorCount
    for ($i = 0; $i -lt $logicalCount; $i++) {
        if (Is-PCore $i) {
            $pCoreIndices += $i
        }
    }
    return $pCoreIndices
}

function Get-SmtSets($logicalCount, $pCores) {
    $smtSets = @()
    $maxSetIndex = [math]::Floor(($logicalCount - 1) / 2)
    for ($set = 0; $set -le $maxSetIndex; $set++) {
        $coreA = $set * 2
        $coreB = $coreA + 1
        if ($coreB -ge $logicalCount) { continue }
        if (($pCores -contains $coreA) -and ($pCores -contains $coreB)) {
            $smtSets += @{ Id = [int]$set; Cores = @($coreA, $coreB) }
        }
    }
    return $smtSets
}

function CoreMaskFromIndex($coreIndex) {
    $maskInt = [uint64](1 -shl $coreIndex)
    return ("{0:X16}" -f $maskInt)
}

function Reserve-Core($core, [ref]$usedCores, [ref]$usedSmtSets, $smtSetId) {
    $usedCores.Value[$core] = $true
    if ($smtSetId -ne $null) { $usedSmtSets.Value[$smtSetId] = $true }
}

function Get-SmtSetIdForCore($core, $smtSets) {
    if ($null -eq $smtSets -or $smtSets.Count -eq 0) { return $null }
    $setId = [int]([math]::Floor($core / 2))
    foreach ($s in $smtSets) {
        if ($s.Id -eq $setId) { return $setId }
    }
    return $null
}

function Find-FreeSmtSetCore([ref]$usedCoresRef, [ref]$usedSmtRef, $smtSets) {
    $freeSets = $smtSets | Where-Object { -not $usedSmtRef.Value.ContainsKey($_.Id) }
    if (-not $freeSets -or $freeSets.Count -eq 0) { return $null }
    $choice = Get-Random -InputObject $freeSets
    foreach ($c in $choice.Cores) {
        if (-not $usedCoresRef.Value.ContainsKey($c)) {
            return @{ Core = $c; SmtId = $choice.Id }
        }
    }
    return $null
}

function Find-FreePCore([ref]$usedCoresRef, [ref]$usedSmtRef, $pCoreIndices, $smtSets) {
    $res = Find-FreeSmtSetCore -usedCoresRef $usedCoresRef -usedSmtRef $usedSmtRef -smtSets $smtSets
    if ($res) { return $res }
    $free = $pCoreIndices | Where-Object { -not $usedCoresRef.Value.ContainsKey($_) }
    if ($free.Count -gt 0) {
        $core = Get-Random -InputObject $free
        $smtId = Get-SmtSetIdForCore -core $core -smtSets $smtSets
        return @{ Core = $core; SmtId = $smtId }
    }
    return $null
}

function Find-FreeECore([ref]$usedCoresRef, $eCoreIndices) {
    if ($eCoreIndices.Count -eq 0) { return $null }
    $free = $eCoreIndices | Where-Object { -not $usedCoresRef.Value.ContainsKey($_) }
    if ($free.Count -gt 0) { return (Get-Random -InputObject $free) }
    return $null
}

function Find-ShareableCore($preferredSharingPartners, [ref]$usedCoresRef, [ref]$usedSmtRef, $smtSets, [bool]$preferSmt, $assignedMap) {
    foreach ($kv in $assignedMap.GetEnumerator()) {
        $dev = $kv.Key
        $coresAssigned = $kv.Value
        $occupantRoles = Get-AutoOptRoles($dev)
        $ok = $false
        foreach ($r in $occupantRoles) { if ($preferredSharingPartners -contains $r) { $ok = $true; break } }
        if (-not $ok) { continue }

        foreach ($c in $coresAssigned) {
            $smtId = Get-SmtSetIdForCore -core $c -smtSets $smtSets
            if ($preferSmt -and $smtId -ne $null) {
                return @{ Core = $c; SmtId = $smtId; ShareMode = 'SMT' }
            } else {
                return @{ Core = $c; SmtId = $smtId; ShareMode = 'Core' }
            }
        }
    }
    return $null
}

$btnAutoOpt.Add_Click({
    try {
        Write-Host "`n[AutoOpt] Starting Auto-Optimization..." -ForegroundColor Cyan
        $logicalCount = [Environment]::ProcessorCount
        $cpu = Get-WmiObject Win32_Processor | Select-Object -First 1
        $physicalCount = $cpu.NumberOfCores
        $htEnabled = ($logicalCount -gt $physicalCount)
        $pCoreIndices = Get-PCoreIndices
        $eCoreIndices = @()
        for ($i = 0; $i -lt $logicalCount; $i++) {
            if (-not ($pCoreIndices -contains $i)) { $eCoreIndices += $i }
        }
        if ($pCoreIndices.Count -gt 0) {
            $pMin = ($pCoreIndices | Measure-Object -Minimum).Minimum
            $pMax = ($pCoreIndices | Measure-Object -Maximum).Maximum
            $cpuLayoutStr = "Cpu $pMin - cpu $pMax are p-cores, other cores are e-cores"
        } else {
            $cpuLayoutStr = "No P-cores detected"
        }
        Write-Host "[AutoOpt] logical=$logicalCount physical=$physicalCount HT=$htEnabled"
        Write-Host "[AutoOpt] P-cores: $($pCoreIndices -join ', ')"
        Write-Host "[AutoOpt] E-cores: $($eCoreIndices -join ', ')"
        Write-Host "[AutoOpt] Layout: $cpuLayoutStr"

        $targetCores = @(0..($logicalCount - 1))
        $core0SoftAvoid = $false
        if ($script:IsDualCCDCpu) {
            $targetCores = $script:Ccd1Cores
            $pCoreIndices = $pCoreIndices | Where-Object { $targetCores -contains $_ }
            $eCoreIndices = $eCoreIndices | Where-Object { $targetCores -contains $_ }
            Write-Host "[AutoOpt] Dual-CCD CPU detected. Restricting all assignments to CCD1 cores: $($targetCores -join ', ')"
            $core0SoftAvoid = $true
        } else {
            if ($hasAudioDevices) {
                $smtId0 = Get-SmtSetIdForCore -core 0 -smtSets $smtSets
                Reserve-Core 0 ([ref]$usedCores) ([ref]$usedSmtSets) $smtId0
                Write-Host "[AutoOpt] Audio detected -> hard-reserved core 0 and SMT set $smtId0"
            } else {
                $core0SoftAvoid = $true
                Write-Host "[AutoOpt] No audio detected -> soft-avoiding core 0 for allocations"
            }
        }

        if ($htEnabled) {
            $smtSets = Get-SmtSets -logicalCount $logicalCount -pCores $pCoreIndices
        } else {
            $smtSets = @()
        }
        $smtCount = if ($smtSets) { $smtSets.Count } else { 0 }
        Write-Host "[AutoOpt] SMT sets available (count=$smtCount):"
        if ($smtCount -gt 0) {
            foreach ($s in $smtSets) { Write-Host "  Set# $($s.Id) => cores $($s.Cores[0]) & $($s.Cores[1])" }
        }
        $usedCores = @{}
        $usedSmtSets = @{}
        $assignedMap = @{}
        $occupiedCores = @()
        $weakOccupiedCores = @()
        $gpus = $deviceList | Where-Object { $_.Category -eq 'PCI' -and $_.Role -eq 'GPU' }
        $nics = $deviceList | Where-Object { $_.Category -eq 'Network' }
        $usbs = $deviceList | Where-Object { $_.Category -eq 'USB' }
        $ssds = $deviceList | Where-Object { $_.Category -eq 'SSD' }
        $audioPCI = $deviceList | Where-Object { $_.Category -eq 'PCI' -and $_.Role -eq 'Audio' }
        $usbSingleAudio = $usbs | Where-Object {
            $norm = Get-AutoOptRoles $_
            ($norm.Count -eq 1) -and ($norm -contains 'Audio')
        }
        $hasAudioDevices = ($audioPCI.Count -gt 0) -or ($usbSingleAudio.Count -gt 0)

        function Find-FreePCoreLocal([ref]$usedCoresRef, [ref]$usedSmtRef, $pCoreIndicesParam, $smtSetsParam, [bool]$avoidCore0) {
            if ($avoidCore0) {
                $smtSetsNo0 = $smtSetsParam | Where-Object { -not ($_.Cores -contains 0) }
                foreach ($s in $smtSetsNo0) {
                    if (-not $usedSmtRef.Value.ContainsKey($s.Id)) {
                        foreach ($c in $s.Cores) {
                            if (-not $usedCoresRef.Value.ContainsKey($c)) {
                                return @{ Core = $c; SmtId = $s.Id }
                            }
                        }
                    }
                }
                $pNo0 = $pCoreIndicesParam | Where-Object { $_ -ne 0 }
                $free = $pNo0 | Where-Object { -not $usedCoresRef.Value.ContainsKey($_) }
                if ($free.Count -gt 0) {
                    $core = Get-Random -InputObject $free
                    $smtId = Get-SmtSetIdForCore -core $core -smtSets $smtSetsParam
                    return @{ Core = $core; SmtId = $smtId }
                }
            }
            foreach ($s in $smtSetsParam) {
                if (-not $usedSmtRef.Value.ContainsKey($s.Id)) {
                    foreach ($c in $s.Cores) {
                        if (-not $usedCoresRef.Value.ContainsKey($c)) {
                            return @{ Core = $c; SmtId = $s.Id }
                        }
                    }
                }
            }
            $freeAll = $pCoreIndicesParam | Where-Object { -not $usedCoresRef.Value.ContainsKey($_) }
            if ($freeAll.Count -gt 0) {
                $core = Get-Random -InputObject $freeAll
                $smtId = Get-SmtSetIdForCore -core $core -smtSets $smtSetsParam
                return @{ Core = $core; SmtId = $smtId }
            }
            return $null
        }

        foreach ($gpu in $gpus) {
            Write-Host "[AutoOpt][GPU] Picking for GPU: $($gpu.DisplayName)"
            $assigned = @()
            $gpuAvoidCore0 = $core0SoftAvoid
            if ($htEnabled -and $smtSets.Count -ge 2) {
                $availableSets = $smtSets | Where-Object { -not $usedSmtSets.ContainsKey($_.Id) }
                $availableSetsNo0 = $availableSets | Where-Object { -not ($_.Cores -contains 0) }
                if ($availableSetsNo0.Count -ge 2) {
                    $chosen = Get-Random -InputObject $availableSetsNo0 -Count 2
                } elseif ($availableSets.Count -ge 2) {
                    $chosen = Get-Random -InputObject $availableSets -Count 2
                } else {
                    $chosen = @()
                }
                foreach ($cset in $chosen) {
                    $coreChoice = $null
                    foreach ($c in $cset.Cores) {
                        if ($c -ne 0 -and -not $usedCores.ContainsKey($c)) { $coreChoice = $c; break }
                    }
                    if ($coreChoice -eq $null) {
                        foreach ($c in $cset.Cores) { if (-not $usedCores.ContainsKey($c)) { $coreChoice = $c; break } }
                    }
                    if ($coreChoice -eq $null) { $coreChoice = $cset.Cores[0] }
                    $assigned += $coreChoice
                    Reserve-Core $coreChoice ([ref]$usedCores) ([ref]$usedSmtSets) $cset.Id
                }
                if ($assigned.Count -lt 2) {
                    $tries = 0
                    while ($assigned.Count -lt 2 -and $tries -lt 200) {
                        $f = Find-FreePCoreLocal -usedCoresRef ([ref]$usedCores) -usedSmtRef ([ref]$usedSmtSets) -pCoreIndicesParam $pCoreIndices -smtSetsParam $smtSets -avoidCore0 $gpuAvoidCore0
                        if ($f -ne $null) {
                            if (-not ($assigned -contains $f.Core)) {
                                $assigned += $f.Core
                                Reserve-Core $f.Core ([ref]$usedCores) ([ref]$usedSmtSets) $f.SmtId
                            }
                        } else { break }
                        $tries++
                    }
                }
            } else {
                $tries = 0
                while ($assigned.Count -lt 2 -and $tries -lt 200) {
                    $f = Find-FreePCoreLocal -usedCoresRef ([ref]$usedCores) -usedSmtRef ([ref]$usedSmtSets) -pCoreIndicesParam $pCoreIndices -smtSetsParam $smtSets -avoidCore0 $gpuAvoidCore0
                    if ($f -ne $null) {
                        $assigned += $f.Core
                        Reserve-Core $f.Core ([ref]$usedCores) ([ref]$usedSmtSets) $f.SmtId
                    } else { break }
                    $tries++
                }
            }
            $assigned = $assigned | Select-Object -Unique
            if ($assigned.Count -eq 0) {
                Write-Host "[AutoOpt][GPU] WARNING - couldn't assign GPU cores" -ForegroundColor Yellow
                $assignedMap[$gpu] = @()
            } else {
                $assignedMap[$gpu] = $assigned
                $maskInt = 0
                foreach ($c in $assigned) { $maskInt = $maskInt -bor (1 -shl $c) }
                $hexMask = "{0:X16}" -f ([uint64]$maskInt)
                Write-Host "[AutoOpt][GPU] Setting GPU affinity: $($gpu.RegistryPath) -> cores [$($assigned -join ', ')] mask 0x$hexMask"
                $res = Set-DeviceAffinity $gpu.RegistryPath ("0x" + $hexMask)
                Write-Host "[AutoOpt][GPU] Set-DeviceAffinity returned: $res"
                $occupiedCores += $assigned
            }
        }

        foreach ($nic in $nics) {
            Write-Host "[AutoOpt][NIC] Assigning NIC: $($nic.DisplayName) Role=$($nic.Role)"
            $f = Find-FreePCoreLocal -usedCoresRef ([ref]$usedCores) -usedSmtRef ([ref]$usedSmtSets) -pCoreIndicesParam $pCoreIndices -smtSetsParam $smtSets -avoidCore0 $core0SoftAvoid
            $shared = $false
            if ($f -eq $null) {
                $preferred = @('Audio','Keyboard','Mouse')
                $share = Find-ShareableCore -preferredSharingPartners $preferred -usedCoresRef ([ref]$usedCores) -usedSmtRef ([ref]$usedSmtSets) -smtSets $smtSets -preferSmt $true -assignedMap $assignedMap
                if ($share) {
                    $f = @{ Core = $share.Core; SmtId = $share.SmtId; Shared = $true }
                    $shared = $true
                    Write-Host "[AutoOpt][NIC] No free P-core; allowing sharing on core $($f.Core) (mode $($share.ShareMode))"
                }
            }
            if ($f -ne $null) {
                $core = $f.Core
                $smtid = $f.SmtId
                if (-not $f.Shared) { Reserve-Core $core ([ref]$usedCores) ([ref]$usedSmtSets) $smtid }
                $assignedMap[$nic] = @($core)
                if ($nic.Role -eq 'NDIS') {
                    try {
                        $valueToSet = "$core"
                        Set-ItemProperty -Path $nic.RegistryPath -Name "*RssBaseProcNumber" -Value $valueToSet -Type String -ErrorAction Stop
                        Write-Host "[AutoOpt][NIC] Wrote *RssBaseProcNumber to $($nic.RegistryPath) -> $valueToSet"
                    } catch {
                        Write-Host "[AutoOpt][NIC] Failed to write *RssBaseProcNumber to $($nic.RegistryPath): $_" -ForegroundColor Yellow
                    }
                } else {
                    $targetRegistryPath = Get-NetworkAdapterAffinityRegistryPath $nic
                    $mask = "{0:X16}" -f ([uint64](1 -shl $core))
                    Write-Host "[AutoOpt][NIC] Setting affinity via Set-DeviceAffinity at $targetRegistryPath -> core $core mask 0x$mask"
                    $res = Set-DeviceAffinity $targetRegistryPath ("0x" + $mask)
                    Write-Host "[AutoOpt][NIC] Set-DeviceAffinity returned: $res"
                }
                $weakOccupiedCores += @($core)
            } else {
                Write-Host "[AutoOpt][NIC] WARNING - could not allocate NIC a P-core" -ForegroundColor Yellow
                $assignedMap[$nic] = @()
            }
        }

        foreach ($usb in $usbs) {
            $roles = Get-AutoOptRoles $usb
            $isControllerRole = ($roles -contains 'Controller')
            $hasMouse = ($roles -contains 'Mouse')
            $singleAudio = ($roles.Count -eq 1 -and $roles -contains 'Audio')
            $singleKeyboard = ($roles.Count -eq 1 -and $roles -contains 'Keyboard')
            $hasOnlyAudioRole = ($roles.Count -eq 1 -and $roles -contains 'Audio')
            Write-Host "[AutoOpt][USB] $($usb.DisplayName) Roles: $($usb.Roles -join ', ')"
            if ($singleAudio -or $hasOnlyAudioRole) {
                $ecore = Find-FreeECore -usedCoresRef ([ref]$usedCores) -eCoreIndices $eCoreIndices
                if ($ecore -ne $null) {
                    Reserve-Core $ecore ([ref]$usedCores) ([ref]$usedSmtSets) $null
                    $assignedMap[$usb] = @($ecore)
                    $mask = "{0:X16}" -f ([uint64](1 -shl $ecore))
                    Write-Host "[AutoOpt][USB] Single-audio USB assigned E-core $ecore mask 0x$mask"
                    $res = Set-DeviceAffinity $usb.RegistryPath ("0x" + $mask)
                    Write-Host "[AutoOpt][USB] Set-DeviceAffinity returned: $res"
                    $weakOccupiedCores += @($ecore)
                    continue
                } else {
                    if (-not $script:IsDualCCDCpu) {
                        $smtId0 = Get-SmtSetIdForCore -core 0 -smtSets $smtSets
                        $core0Available = (-not $usedCores.ContainsKey(0)) -and ($smtId0 -eq $null -or -not $usedSmtSets.ContainsKey($smtId0))
                        if ($core0Available) {
                            Reserve-Core 0 ([ref]$usedCores) ([ref]$usedSmtSets) $smtId0
                            $assignedMap[$usb] = @(0)
                            $mask = "{0:X16}" -f ([uint64](1 -shl 0))
                            Write-Host "[AutoOpt][USB] No E-core; assigned core 0 mask 0x$mask"
                            $res = Set-DeviceAffinity $usb.RegistryPath ("0x" + $mask)
                            Write-Host "[AutoOpt][USB] Set-DeviceAffinity returned: $res"
                            if ($isControllerRole) { $occupiedCores += @([int]0) }
                            if ($hasMouse) { $occupiedCores += @([int]0) }
                            if ($singleKeyboard) { $weakOccupiedCores += @([int]0) }
                            if ($singleAudio) { $weakOccupiedCores += @([int]0) }
                            continue
                        }
                    }
                    Write-Host "[AutoOpt][USB] No E-core and core-0 unavailable or forbidden; falling back to P-core"
                }
            }
            $f = Find-FreePCoreLocal -usedCoresRef ([ref]$usedCores) -usedSmtRef ([ref]$usedSmtSets) -pCoreIndicesParam $pCoreIndices -smtSetsParam $smtSets -avoidCore0 $core0SoftAvoid
            if ($f -eq $null) {
                $preferred = @('Audio','Keyboard')
                $share = Find-ShareableCore -preferredSharingPartners $preferred -usedCoresRef ([ref]$usedCores) -usedSmtRef ([ref]$usedSmtSets) -smtSets $smtSets -preferSmt $true -assignedMap $assignedMap
                if ($share) {
                    $f = @{ Core = $share.Core; SmtId = $share.SmtId; Shared = $true }
                    Write-Host "[AutoOpt][USB] No free P-core; allowing sharing on core $($f.Core) (mode $($share.ShareMode))"
                }
            }
            if ($f -ne $null) {
                $core = $f.Core
                $smtid = $f.SmtId
                if (-not $f.Shared) { Reserve-Core $core ([ref]$usedCores) ([ref]$usedSmtSets) $smtid }
                $assignedMap[$usb] = @($core)
                $mask = "{0:X16}" -f ([uint64](1 -shl $core))
                Write-Host "[AutoOpt][USB] Setting USB affinity: $($usb.RegistryPath) -> core $core mask 0x$mask"
                $res = Set-DeviceAffinity $usb.RegistryPath ("0x" + $mask)
                Write-Host "[AutoOpt][USB] Set-DeviceAffinity returned: $res"
                if ($isControllerRole) { $occupiedCores += @($core) }
                if ($hasMouse) { $occupiedCores += @($core) }
                if ($singleKeyboard) { $weakOccupiedCores += @($core) }
            } else {
                Write-Host "[AutoOpt][USB] WARNING - could not allocate P-core for USB $($usb.DisplayName)" -ForegroundColor Yellow
                $assignedMap[$usb] = @()
            }
        }

        foreach ($aud in $audioPCI) {
            Write-Host "[AutoOpt][AudioPCI] Assigning: $($aud.DisplayName)"
            $ecore = Find-FreeECore -usedCoresRef ([ref]$usedCores) -eCoreIndices $eCoreIndices
            if ($ecore -ne $null) {
                Reserve-Core $ecore ([ref]$usedCores) ([ref]$usedSmtSets) $null
                $assignedMap[$aud] = @($ecore)
                $mask = "{0:X16}" -f ([uint64](1 -shl $ecore))
                Write-Host "[AutoOpt][AudioPCI] Assigned E-core $ecore mask 0x$mask"
                $res = Set-DeviceAffinity $aud.RegistryPath ("0x" + $mask)
                Write-Host "[AutoOpt][AudioPCI] Set-DeviceAffinity returned: $res"
                $weakOccupiedCores += @($ecore)
            } else {
                if (-not $script:IsDualCCDCpu) {
                    $smtId0 = Get-SmtSetIdForCore -core 0 -smtSets $smtSets
                    $core0Available = (-not $usedCores.ContainsKey(0)) -and ($smtId0 -eq $null -or -not $usedSmtSets.ContainsKey($smtId0))
                    if ($core0Available) {
                        Reserve-Core 0 ([ref]$usedCores) ([ref]$usedSmtSets) $smtId0
                        $assignedMap[$aud] = @(0)
                        $mask = "{0:X16}" -f ([uint64](1 -shl 0))
                        Write-Host "[AutoOpt][AudioPCI] No E-core; assigned core 0 mask 0x$mask"
                        $res = Set-DeviceAffinity $aud.RegistryPath ("0x" + $mask)
                        Write-Host "[AutoOpt][AudioPCI] Set-DeviceAffinity returned: $res"
                        $weakOccupiedCores += @([int]0)
                        continue
                    }
                }
                $f = Find-FreePCoreLocal -usedCoresRef ([ref]$usedCores) -usedSmtRef ([ref]$usedSmtSets) -pCoreIndicesParam $pCoreIndices -smtSetsParam $smtSets -avoidCore0 $core0SoftAvoid
                if ($f -ne $null) {
                    $core = $f.Core
                    Reserve-Core $core ([ref]$usedCores) ([ref]$usedSmtSets) $f.SmtId
                    $assignedMap[$aud] = @($core)
                    $mask = "{0:X16}" -f ([uint64](1 -shl $core))
                    Write-Host "[AutoOpt][AudioPCI] No E-core; assigned P-core $core mask 0x$mask"
                    $res = Set-DeviceAffinity $aud.RegistryPath ("0x" + $mask)
                    Write-Host "[AutoOpt][AudioPCI] Set-DeviceAffinity returned: $res"
                    $weakOccupiedCores += @($core)
                } else {
                    Write-Host "[AutoOpt][AudioPCI] WARNING - could not assign Audio PCI" -ForegroundColor Yellow
                    $assignedMap[$aud] = @()
                }
            }
        }

        foreach ($dev in $deviceList) {
            $msiPath = if ($dev.Category -eq "Network") { Get-NetworkAdapterMSIRegistryPath $dev } else { $dev.RegistryPath }
            if ($dev.Category -eq "Network") {
                Write-Host "[AutoOpt] Skipping MSI changes for NIC: $($dev.DisplayName) at path $msiPath"
                $priRes = Set-DevicePriority $msiPath 3
                Write-Host "[AutoOpt] Set-DevicePriority for NIC $($dev.DisplayName) -> 3 (High): $priRes"
                $msiInfo = Get-CurrentMSI $msiPath
                $msgLimitDebug = if ($msiInfo.MessageLimit -eq "") { "Unlimited" } else { $msiInfo.MessageLimit.ToString() }
                Write-Host "[AutoOpt] NIC MSI status read (no change): MSIEnabled=$($msiInfo.MSIEnabled) MessageLimit=$msgLimitDebug"
                continue
            }
            if ($dev.Category -eq 'SSD') {
                $chosenMsgLimit = ""  
                $msiRes = Set-DeviceMSI $msiPath 1 $chosenMsgLimit
                $msgLimitDebug = if ($chosenMsgLimit -eq "") { "Unlimited" } else { $chosenMsgLimit }
                Write-Host "[AutoOpt] Set-DeviceMSI for SSD $($dev.DisplayName) -> Enabled (MessageLimit=$msgLimitDebug) result: $msiRes"
                $priRes = Set-DevicePriority $msiPath 3
                Write-Host "[AutoOpt] Set-DevicePriority for SSD $($dev.DisplayName) -> 3 (High): $priRes"
                continue
            }
            $chosenMsgLimit = ""  
            $msiRes = Set-DeviceMSI $msiPath 1 $chosenMsgLimit
            $msgLimitDebug = if ($chosenMsgLimit -eq "") { "Unlimited" } else { $chosenMsgLimit }
            Write-Host "[AutoOpt] Set-DeviceMSI for $($dev.DisplayName) at $msiPath -> Enabled (MessageLimit=$msgLimitDebug) result: $msiRes"
            $priRes = Set-DevicePriority $msiPath 3
            Write-Host "[AutoOpt] Set-DevicePriority for $($dev.DisplayName) -> 3 (High): $priRes"
        }

        foreach ($usb in $usbs) {
            $assigned = $assignedMap[$usb]
            if (-not $assigned) { continue }
            if ($usb.Roles -contains 'Controller' -or $usb.Roles -contains 'Mouse') {
                $occupiedCores += $assigned
            }
            $norm = Get-AutoOptRoles $usb
            if (($norm.Count -eq 1) -and ($norm -contains 'Audio')) {
                $weakOccupiedCores += $assigned
            }
        }

        foreach ($usb in $usbs) {
            $assigned = $assignedMap[$usb]
            if (-not $assigned) { continue }
            $normRoles = Get-AutoOptRoles $usb
            $hasAudio = ($normRoles -contains 'Audio')
            $hasKeyboard = ($normRoles -contains 'Keyboard')
            $otherRoles = $normRoles | Where-Object { $_ -ne 'Audio' -and $_ -ne 'Keyboard' }
            if ($hasAudio -and $hasKeyboard -and ($otherRoles.Count -eq 0)) {
                Write-Host "[AutoOpt] Mixed Audio+Keyboard USB -> adding to weakOccupiedCores: $($usb.DisplayName) -> cores [$($assigned -join ', ')]"
                $weakOccupiedCores += $assigned
            }
        }

        foreach ($gpu in $gpus) {
            $assigned = $assignedMap[$gpu]
            if ($assigned) { $occupiedCores += $assigned }
        }

        foreach ($nic in $nics) {
            $assigned = $assignedMap[$nic]
            if ($assigned) { $weakOccupiedCores += $assigned }
        }

        $occupiedCores = ($occupiedCores | Select-Object -Unique) | Sort-Object
        $weakOccupiedCores = ($weakOccupiedCores | Select-Object -Unique) | Sort-Object
        Write-Host "[AutoOpt] Final occupied_cores (strong): $($occupiedCores -join ', ')" -ForegroundColor Green
        Write-Host "[AutoOpt] Final occupied_weak_cores: $($weakOccupiedCores -join ', ')" -ForegroundColor Green

        $scriptPath = $MyInvocation.MyCommand.Path
        $scriptDir = if ($scriptPath) { Split-Path -Parent $scriptPath } else { Get-Location }
        $gamesCfgPath = Join-Path $scriptDir "games_priorities.cfg"
        $systemCfgPath = Join-Path $scriptDir "system_priorities.cfg"

        function Write-ConfigFileEntriesLocal {
            param($path, $coresArr, $weakArr)
            $coresString = ($coresArr -join ',')
            $weakString = ($weakArr -join ',')
            if (-not (Test-Path $path)) { New-Item -Path $path -ItemType File -Force | Out-Null }
            $content = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
            if ($content -match '(?m)^occupied_affinity_cores=.*$') { $content = $content -replace '(?m)^occupied_affinity_cores=.*$', "occupied_affinity_cores=$coresString" } else { $content += "`r`noccupied_affinity_cores=$coresString" }
            if ($content -match '(?m)^occupied_ideal_processor_cores=.*$') { $content = $content -replace '(?m)^occupied_ideal_processor_cores=.*$', "occupied_ideal_processor_cores=$coresString" } else { $content += "`r`noccupied_ideal_processor_cores=$coresString" }
            if ($content -match '(?m)^occupied_weak_affinity_cores=.*$') { $content = $content -replace '(?m)^occupied_weak_affinity_cores=.*$', "occupied_weak_affinity_cores=$weakString" } else { $content += "`r`noccupied_weak_affinity_cores=$weakString" }
            if ($content -match '(?m)^occupied_weak_ideal_processor_cores=.*$') { $content = $content -replace '(?m)^occupied_weak_ideal_processor_cores=.*$', "occupied_weak_ideal_processor_cores=$weakString" } else { $content += "`r`noccupied_weak_ideal_processor_cores=$weakString" }
            [System.IO.File]::WriteAllText($path, $content.Trim(), [System.Text.UTF8Encoding]::new($false))
            Write-Host "[AutoOpt] Wrote config entries to $path"
        }

        Write-ConfigFileEntriesLocal -path $gamesCfgPath -coresArr $occupiedCores -weakArr $weakOccupiedCores
        Write-ConfigFileEntriesLocal -path $systemCfgPath -coresArr $occupiedCores -weakArr $weakOccupiedCores

        try { Refresh-DeviceUI; Write-Host "[AutoOpt] GUI refreshed" -ForegroundColor Cyan } catch { Write-Host "[AutoOpt] GUI refresh failed: $_" -ForegroundColor Yellow }
        [System.Windows.Forms.MessageBox]::Show("Auto-optimization finished. A system restart may be required.", "Auto-Optimization")
        Write-Host "[AutoOpt] Completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "[AutoOpt] Error: $_" -ForegroundColor Red
        [System.Windows.Forms.MessageBox]::Show("Auto-optimization failed: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

[void]$form.ShowDialog()

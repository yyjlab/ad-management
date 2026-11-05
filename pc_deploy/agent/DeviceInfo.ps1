# Read-only, best-effort hardware inventory shared by PE and the installed-system callback.
function Get-DeploymentDeviceInfo {
    param([ValidateSet('pe','windows')][string]$Stage)
    if ($script:DeploymentInfoCache -and $script:DeploymentInfoCache.stage -eq $Stage -and
        ([DateTime]::UtcNow - $script:DeploymentInfoCache.time).TotalSeconds -lt 60) {
        return $script:DeploymentInfoCache.value
    }
    function Read-DeviceCim([string]$Class, [string[]]$Properties, [string]$Filter = '') {
        try {
            $queryArgs = @{ClassName=$Class;Property=$Properties;OperationTimeoutSec=3;ErrorAction='Stop'}
            if ($Filter) { $queryArgs.Filter=$Filter }
            Get-CimInstance @queryArgs
        } catch { }
    }
    $info = @{computer_name=[string]$env:COMPUTERNAME}
    $cs = Read-DeviceCim 'Win32_ComputerSystem' @('Domain','PartOfDomain','TotalPhysicalMemory')
    if ($cs) {
        $info.domain=[string]$cs.Domain; $info.part_of_domain=[bool]$cs.PartOfDomain
        $info.ram_bytes=[long]$cs.TotalPhysicalMemory
    }
    $info.cpus = @(Read-DeviceCim 'Win32_Processor' @('Name','NumberOfCores','NumberOfLogicalProcessors','MaxClockSpeed') |
        Select-Object -First 8 | ForEach-Object {
            @{name=[string]$_.Name;cores=[int]$_.NumberOfCores;threads=[int]$_.NumberOfLogicalProcessors;max_mhz=[int]$_.MaxClockSpeed}
        })
    $info.memory_modules = @(Read-DeviceCim 'Win32_PhysicalMemory' @('DeviceLocator','Capacity','Speed','Manufacturer','PartNumber') |
        Select-Object -First 32 | ForEach-Object {
            @{slot=[string]$_.DeviceLocator;capacity_bytes=[long]$_.Capacity;speed_mhz=[int]$_.Speed;
              manufacturer=[string]$_.Manufacturer;part_number=([string]$_.PartNumber).Trim()}
        })
    $bios = Read-DeviceCim 'Win32_BIOS' @('Manufacturer','SMBIOSBIOSVersion')
    if ($bios) { $info.bios_manufacturer=[string]$bios.Manufacturer; $info.bios_version=[string]$bios.SMBIOSBIOSVersion }
    $board = @(Read-DeviceCim 'Win32_BaseBoard' @('Manufacturer','Product','SerialNumber') | Select-Object -First 1)
    if ($board.Count) {
        $info.board_manufacturer=[string]$board[0].Manufacturer; $info.board_model=[string]$board[0].Product
        $info.board_serial=[string]$board[0].SerialNumber
    }
    $info.gpus = @(Read-DeviceCim 'Win32_VideoController' @('Name','DriverVersion') | Select-Object -First 8 |
        ForEach-Object { @{name=[string]$_.Name;driver_version=[string]$_.DriverVersion} })
    $adapters = @(Read-DeviceCim 'Win32_NetworkAdapter' @('Index','Speed','Name','MACAddress','PhysicalAdapter') 'PhysicalAdapter=True' | Select-Object -First 16)
    $addresses = @(Read-DeviceCim 'Win32_NetworkAdapterConfiguration' @('Index','IPAddress') 'IPEnabled=True')
    $info.networks = @($adapters | ForEach-Object {
        $nic=$_; $ip=@($addresses | Where-Object { $_.Index -eq $nic.Index } | ForEach-Object { $_.IPAddress })
        @{name=[string]$nic.Name;mac=[string]$nic.MACAddress;addresses=@($ip | Select-Object -First 16);
          link_mbps=[long]([double]$nic.Speed / 1000000)}
    })
    if ($Stage -eq 'windows') {
        $os = Read-DeviceCim 'Win32_OperatingSystem' @('Caption','Version','BuildNumber','OSArchitecture')
        if ($os) { $info.os_name=[string]$os.Caption; $info.os_version=[string]$os.Version;
            $info.os_build=[string]$os.BuildNumber; $info.os_architecture=[string]$os.OSArchitecture }
        $info.volumes = @(Read-DeviceCim 'Win32_LogicalDisk' @('DeviceID','FileSystem','Size','FreeSpace') 'DriveType=3' |
            Select-Object -First 32 | ForEach-Object {
                @{letter=[string]$_.DeviceID;filesystem=[string]$_.FileSystem;size_bytes=[long]$_.Size;free_bytes=[long]$_.FreeSpace}
            })
    }
    $script:DeploymentInfoCache=@{stage=$Stage;time=[DateTime]::UtcNow;value=$info}
    return $info
}

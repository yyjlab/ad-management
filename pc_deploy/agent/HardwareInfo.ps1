# Optional PE-only hardware inventory. Read-only CIM/registry queries; no disk/filesystem changes.
function ConvertFrom-DeploymentEdid {
    param([byte[]]$Bytes)
    $result=@{EdidValid=$false}
    if(-not $Bytes -or $Bytes.Length -lt 128){return $result}
    $base=[byte[]]$Bytes[0..127]
    $result.EdidBase64=[Convert]::ToBase64String($base)
    if([BitConverter]::ToString($base[0..7]) -ne '00-FF-FF-FF-FF-FF-FF-00'){return $result}
    $sum=0;foreach($value in $base){$sum+=[int]$value}
    if(($sum % 256) -ne 0){return $result}
    $result.EdidValid=$true
    $vendor=([int]$base[8] -shl 8) -bor [int]$base[9]
    $code='';foreach($shift in @(10,5,0)){
        $letter=($vendor -shr $shift) -band 31
        if($letter -lt 1 -or $letter -gt 26){$code='';break}
        $code += [char](64+$letter)
    }
    if($code){$result.Manufacturer=$code}
    $result.ProductCode=('{0:X4}' -f [BitConverter]::ToUInt16($base,10))
    $serial=[BitConverter]::ToUInt32($base,12)
    if($serial -gt 0){$result.SerialNumber=[string]$serial}
    $result.ManufactureYear=1990+[int]$base[17]
    if($base[16] -gt 0 -and $base[16] -lt 54){$result.ManufactureWeek=[int]$base[16]}
    $result.EdidVersion=([string]$base[18])+'.'+([string]$base[19])
    $result.DigitalInput=($base[20] -band 128) -ne 0
    if($base[21] -gt 0 -and $base[22] -gt 0){
        $result.WidthCm=[int]$base[21];$result.HeightCm=[int]$base[22]
        $result.DiagonalInches=[Math]::Round([Math]::Sqrt([Math]::Pow($base[21],2)+[Math]::Pow($base[22],2))/2.54,1)
    }
    for($offset=54;$offset -le 108;$offset+=18){
        if($base[$offset] -eq 0 -and $base[$offset+1] -eq 0 -and $base[$offset+2] -eq 0){
            $text=[Text.Encoding]::ASCII.GetString($base,$offset+5,13).Trim([char[]]@(0,10,13,32))
            if($text -and $base[$offset+3] -eq 252){$result.Name=$text}
            if($text -and $base[$offset+3] -eq 255){$result.SerialNumber=$text}
        }elseif(-not $result.ContainsKey('PreferredResolution')){
            $horizontal=[int]$base[$offset+2]+(([int]$base[$offset+4] -band 240) -shl 4)
            $vertical=[int]$base[$offset+5]+(([int]$base[$offset+7] -band 240) -shl 4)
            if($horizontal -gt 0 -and $vertical -gt 0){
                $result.PreferredResolution="$horizontal x $vertical"
            }
        }
    }
    return $result
}

function Read-DeploymentHardwareRaw {
    param([string]$Key,[string]$Class,[string[]]$Properties,[int]$Limit,
          [hashtable]$Statuses,[Diagnostics.Stopwatch]$Clock,[string]$Namespace='root/cimv2')
    if($Clock.Elapsed.TotalSeconds -ge 20){$Statuses[$Key]='budget_exceeded';return}
    try{
        $rows=@(Get-CimInstance -Namespace $Namespace -ClassName $Class -Property $Properties -OperationTimeoutSec 2 -ErrorAction Stop | Select-Object -First ($Limit+1))
        $Statuses[$Key]=if($rows.Count -gt $Limit){'truncated'}elseif($rows.Count){'ok'}else{'empty'}
        $rows | Select-Object -First $Limit
    }catch{$Statuses[$Key]='unavailable'}
}

function Read-DeploymentEdidRegistry {
    # Only the currently running PE's live hardware hive, never an offline Windows hive.
    try{
        foreach($vendor in @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY' -ErrorAction Stop | Select-Object -First 32)){
            foreach($instance in @(Get-ChildItem -LiteralPath $vendor.PSPath -ErrorAction SilentlyContinue | Select-Object -First 16)){
                try{
                    $parameters=Get-ItemProperty -LiteralPath ($instance.PSPath+'\Device Parameters') -Name EDID -ErrorAction Stop
                    if($parameters.EDID){@{InstanceName=('DISPLAY\'+$vendor.PSChildName+'\'+$instance.PSChildName);Bytes=[byte[]]$parameters.EDID}}
                }catch{}
            }
        }
    }catch{}
}

function Get-DeploymentMonitorInventory {
    param([hashtable]$Statuses,[Diagnostics.Stopwatch]$Clock)
    $monitors=@{}
    $ids=@(Read-DeploymentHardwareRaw 'monitor_ids' 'WmiMonitorID' @('InstanceName','Active','ManufacturerName','UserFriendlyName','SerialNumberID','ProductCodeID','WeekOfManufacture','YearOfManufacture') 16 $Statuses $Clock 'root/wmi')
    foreach($id in $ids){
        $key=([string]$id.InstanceName) -replace '_\d+$',''
        if(-not $key){continue}
        $row=@{InstanceName=$key;Source='WMI'}
        if($null -ne $id.Active){$row.Active=[bool]$id.Active}
        foreach($pair in @(@('Manufacturer','ManufacturerName'),@('Name','UserFriendlyName'),@('SerialNumber','SerialNumberID'),@('ProductCode','ProductCodeID'))){
            $raw=$id.($pair[1])
            $value=-join @($raw | Where-Object {$_ -gt 0 -and $_ -lt 127} | ForEach-Object {[char]$_})
            if($value.Trim()){$row[$pair[0]]=$value.Trim()}
        }
        if($id.YearOfManufacture -gt 0){$row.ManufactureYear=[int]$id.YearOfManufacture}
        if($id.WeekOfManufacture -gt 0 -and $id.WeekOfManufacture -lt 54){$row.ManufactureWeek=[int]$id.WeekOfManufacture}
        $monitors[$key]=$row
    }
    $read=0
    foreach($entry in @(Read-DeploymentEdidRegistry | Select-Object -First 16)){
        try{
            $key=[string]$entry.InstanceName;if(-not $key){continue}
            $parsed=ConvertFrom-DeploymentEdid -Bytes $entry.Bytes
            if(-not $monitors.ContainsKey($key)){$monitors[$key]=@{InstanceName=$key;Source='EDID'}}
            elseif($parsed.EdidValid){$monitors[$key].Source='WMI + EDID'}
            foreach($name in $parsed.Keys){$monitors[$key][$name]=$parsed[$name]}
            $read++
        }catch{}
    }
    $Statuses.monitor_edid=if($read){'ok'}else{'empty'}
    $connections=@(Read-DeploymentHardwareRaw 'monitor_connections' 'WmiMonitorConnectionParams' @('InstanceName','VideoOutputTechnology') 16 $Statuses $Clock 'root/wmi')
    foreach($connection in $connections){
        $key=([string]$connection.InstanceName) -replace '_\d+$',''
        if($monitors.ContainsKey($key) -and $null -ne $connection.VideoOutputTechnology){
            $kind=[long]$connection.VideoOutputTechnology
            $monitors[$key].ConnectionType=$kind
            if($kind -in @(6,11,13,2147483648)){$monitors[$key].IsInternal=$true}
            elseif($kind -in @(0,1,2,3,4,5,8,9,10,12,15,16)){$monitors[$key].IsInternal=$false}
        }
    }
    @($monitors.Values | Sort-Object InstanceName | Select-Object -First 16)
}

function Get-DeploymentHardwareInfo {
    param([switch]$Refresh)
    if(-not $Refresh -and $script:DeploymentHardwareInfoCache -and
       ([DateTime]::UtcNow-$script:DeploymentHardwareInfoCache.time).TotalSeconds -lt 300){
        return $script:DeploymentHardwareInfoCache.value
    }
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $statuses=@{}
    $result=@{schema_version=1;query_status=$statuses}
    $result.monitors=@(Get-DeploymentMonitorInventory $statuses $clock)
    $specs=@(
        @{Key='system';Class='Win32_ComputerSystemProduct';Limit=1;Fields=@('Vendor','Name','Version','IdentifyingNumber','UUID','SKUNumber')},
        @{Key='chassis';Class='Win32_SystemEnclosure';Limit=4;Fields=@('Manufacturer','Model','SerialNumber','SMBIOSAssetTag','ChassisTypes')},
        @{Key='processors';Class='Win32_Processor';Limit=8;Fields=@('Name','Manufacturer','ProcessorId','SocketDesignation','Architecture','AddressWidth','DataWidth','NumberOfCores','NumberOfLogicalProcessors','MaxClockSpeed','L2CacheSize','L3CacheSize','VirtualizationFirmwareEnabled')},
        @{Key='memory';Class='Win32_PhysicalMemory';Limit=32;Fields=@('DeviceLocator','BankLabel','Manufacturer','PartNumber','SerialNumber','Capacity','Speed','ConfiguredClockSpeed','FormFactor','SMBIOSMemoryType','TotalWidth','DataWidth')},
        @{Key='disk_drives';Class='Win32_DiskDrive';Limit=32;Fields=@('Index','Model','SerialNumber','FirmwareRevision','Size','InterfaceType','MediaType','PNPDeviceID','Status')},
        @{Key='physical_disks';Class='MSFT_PhysicalDisk';Namespace='root/Microsoft/Windows/Storage';Limit=32;Fields=@('FriendlyName','SerialNumber','MediaType','BusType','Size','FirmwareVersion','HealthStatus','OperationalStatus','SpindleSpeed','PhysicalLocation')},
        @{Key='graphics';Class='Win32_VideoController';Limit=8;Fields=@('Name','AdapterCompatibility','VideoProcessor','AdapterRAM','PNPDeviceID','DriverVersion','VideoModeDescription','CurrentHorizontalResolution','CurrentVerticalResolution','CurrentRefreshRate','Status')},
        @{Key='bios';Class='Win32_BIOS';Limit=1;Fields=@('Manufacturer','Name','SMBIOSBIOSVersion','Version','SerialNumber','ReleaseDate','SMBIOSMajorVersion','SMBIOSMinorVersion')},
        @{Key='baseboards';Class='Win32_BaseBoard';Limit=4;Fields=@('Manufacturer','Product','Version','SerialNumber','PartNumber','Status')},
        @{Key='network_adapters';Class='Win32_NetworkAdapter';Limit=32;Fields=@('Name','Manufacturer','MACAddress','PNPDeviceID','AdapterType','Speed','PhysicalAdapter','NetEnabled','NetConnectionStatus')},
        @{Key='network_config';Class='Win32_NetworkAdapterConfiguration';Limit=32;Fields=@('Description','MACAddress','IPAddress','IPSubnet','DefaultIPGateway','DNSServerSearchOrder','DHCPEnabled','DHCPServer','DNSDomain')},
        @{Key='batteries';Class='Win32_Battery';Limit=8;Fields=@('Name','DeviceID','PNPDeviceID','BatteryStatus','EstimatedChargeRemaining','DesignCapacity','FullChargeCapacity','DesignVoltage','Status')},
        @{Key='sound';Class='Win32_SoundDevice';Limit=16;Fields=@('Name','Manufacturer','PNPDeviceID','Status')},
        @{Key='keyboards';Class='Win32_Keyboard';Limit=16;Fields=@('Name','Description','Layout','NumberOfFunctionKeys','PNPDeviceID','Status')},
        @{Key='pointing_devices';Class='Win32_PointingDevice';Limit=16;Fields=@('Name','Manufacturer','PointingType','NumberOfButtons','DeviceInterface','PNPDeviceID','Status')},
        @{Key='ports';Class='Win32_PortConnector';Limit=32;Fields=@('ExternalReferenceDesignator','InternalReferenceDesignator','PortType','ConnectorType')},
        @{Key='pnp_devices';Class='Win32_PnPEntity';Limit=64;Fields=@('Name','Manufacturer','PNPClass','PNPDeviceID','HardwareID','Service','ConfigManagerErrorCode','Status')}
    )
    foreach($spec in $specs){
        $namespace=if($spec.Namespace){$spec.Namespace}else{'root/cimv2'}
        $rows=@(Read-DeploymentHardwareRaw $spec.Key $spec.Class $spec.Fields $spec.Limit $statuses $clock $namespace)
        $result[$spec.Key]=@($rows | ForEach-Object {
            $row=@{}
            foreach($field in $spec.Fields){
                $value=$_.($field)
                if($null -eq $value){continue}
                if($value -is [bool]){$row[$field]=$value}
                elseif($value -is [DateTime]){$row[$field]=$value.ToUniversalTime().ToString('o')}
                elseif($value -is [ValueType]){$row[$field]=$value}
                else{
                    $text=(@($value | Select-Object -First 8) -join '; ') -replace '[\x00-\x1f\x7f]',' '
                    $text=$text.Trim()
                    if($text){$row[$field]=$text.Substring(0,[Math]::Min(160,$text.Length))}
                }
            }
            if($row.Count){$row}
        })
    }
    # Preserve the platform's existing request ceiling; trim optional groups before upload.
    foreach($key in @('pnp_devices','ports','network_adapters','disk_drives','network_config','keyboards','pointing_devices','sound','batteries','graphics','memory','baseboards','chassis','system','bios','physical_disks','monitors')){
        if([Text.Encoding]::UTF8.GetByteCount(($result | ConvertTo-Json -Depth 8 -Compress)) -le 98304){break}
        $result[$key]=@();$statuses[$key]='size_limit'
    }
    $result.duration_ms=[long]$clock.ElapsedMilliseconds
    $script:DeploymentHardwareInfoCache=@{time=[DateTime]::UtcNow;value=$result}
    return $result
}

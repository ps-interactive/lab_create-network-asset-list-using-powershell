# Set the list of IP addresses to scan
$ip_addresses = Get-Content C:\Users\Public\Desktop\ip.txt
$ports = 21,22,80,138,139,443,445

# Create an empty array to store the results
$asset_results = @()

# Loop through each IP address and gather information
foreach ($ip in $ip_addresses) {
		$open_ports = @()

    $online = Test-Connection -ComputerName $ip -Count 1 -Quiet
		$dns_name = (Resolve-DnsName -Name $ip -ErrorAction SilentlyContinue).NameHost
		foreach ($port in $ports) {
        $is_open = $port | % {echo ((new-object Net.Sockets.TcpClient).Connect($ip, $_)) "$_"} 2>$null
				if ($is_open -eq $null) {}
        else {
					$open_ports += $port
					if ($port = 139) {
                $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ip 2>$null
                $os_name = $os.Caption
                $os_ver = $os.Version

								$proc = Get-WmiObject -Class Win32_Processor -ComputerName $ip 2>$null
                $proc_name = $proc.Name
                $proc_cores = $proc.NumberOfCores

                $sys = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ip 2>$null
                $sys_domain = $sys.Domain
                $sys_name = $sys.Name

                $net = Get-WMIObject -Class Win32_NetworkAdapter -ComputerName $ip -Filter NetConnectionStatus=2 2>$null
                $net_mac = $net.Macaddress
					}
					else {}
				}
		$obj = New-Object PSObject -Property @{
        "ip" = $ip
        "Online" = $online
				"DNS Name" = $dns_name
				"Open Ports" = $open_ports -join ","
				"OS Name" = $os_name
        "OS Version" = $os_ver
				"Processor" = $proc_name
        "Number of Cores" = $proc_cores
        "System Name" = $sys_name
        "Domain" = $sys_domain
        "MAC Address" = $net_mac -join ","
		}
	}
# Add the object to the results array
    $asset_results += $obj
}

$asset_results | Format-Table -AutoSize

$asset_results | Export-Csv -Path "C:\Users\pslearner\Desktop\asset_list.csv" -NoTypeInformation
$asset_results | Out-File -FilePath "C:\Users\pslearner\Desktop\asset_list.txt"

<powershell>
# Post Reboot Retry script
# Start transcript for logging
$VerbosePreference = "Continue"
$logPath = "C:\ECS_Setup_Transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Start-Transcript -Path $logPath -Force
Write-Host "Started transcript logging at $logPath"
Write-Host "###I will retry execution if process is interrupted due to externally triggered reboots###"

$scriptPath = $MyInvocation.MyCommand.Definition
$taskName = "ECSSetupStartupTask"
$markerFile = "C:\ProgramData\ECSSetupRunning.marker"

# --- Schedule the script to run at startup if not already scheduled ---
if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
    Write-Host "Scheduling script to run at startup..."
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
	$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
	$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
} else {
    Write-Host "Startup scheduled task already exists."
}

# --- Check for marker file to detect recovery run ---
if (Test-Path $markerFile) {
    Write-Host "Recovery run detected: previous execution did not complete."
} else {
    Write-Host "Clean run detected."
}

# --- Create marker file to indicate script is running ---
New-Item -Path $markerFile -ItemType File -Force | Out-Null
Write-Host "Marker file created at $markerFile"

# --- Core script begins here ---

### Install depedencies

# Ensure the NuGet provider is present (manual install workaround)
$nugetUrl = "https://onegetcdn.azureedge.net/providers/Microsoft.PackageManagement.NuGetProvider-2.8.5.208.dll"
$nugetDest = "$env:ProgramFiles\PackageManagement\ProviderAssemblies\nuget\2.8.5.208"

# Create directory if missing
if (-not (Test-Path $nugetDest)) {
    New-Item -ItemType Directory -Path $nugetDest -Force | Out-Null
}

$nugetDll = Join-Path $nugetDest "Microsoft.PackageManagement.NuGetProvider.dll"

if (-not (Test-Path $nugetDll)) {
    Write-Host "Downloading NuGet provider manually..."
    Invoke-WebRequest -Uri $nugetUrl -OutFile $nugetDll
    Write-Host "NuGet provider downloaded to $nugetDll"
} else {
    Write-Host "NuGet provider already present at $nugetDll"
}

# Check if NuGet provider is already imported
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Write-Host "Importing NuGet package provider..."
    Import-PackageProvider -Name NuGet -Force -ErrorAction Stop
    Write-Host "NuGet package provider imported."
} else {
    Write-Host "NuGet package provider already available."
}

# Ensure AWS PowerShell module is installed
if (-not (Get-Module -ListAvailable -Name AWSPowerShell.NetCore)) {
    Write-Host "Installing AWS PowerShell module..."
    Install-Module -Name AWSPowerShell.NetCore -Force -Scope AllUsers -AllowClobber
    Write-Host "AWS PowerShell module installed."
} else {
    Write-Host "AWS PowerShell module already available."
}

# Import AWS module only if not already imported in the session
if (-not (Get-Module -Name AWSPowerShell.NetCore)) {
    Import-Module AWSPowerShell.NetCore -ErrorAction Stop
    Write-Host "AWS PowerShell module imported."
} else {
    Write-Host "AWS PowerShell module already imported in this session."
}

### Domain join

Write-Host "Check and Domain join if needed..."
$domain = "product.company.com"

# AWS Managed Microsoft AD DNS IP addresses
$dnsServers = @("10.105.208.190", "10.105.208.70")

# Get the primary network adapter name (usually "Ethernet")
$interface = Get-DnsClient | Where-Object { $_.InterfaceAlias -ne "Loopback Pseudo-Interface 1" } | Select-Object -First 1

if ($interface) {
    Write-Host "Setting DNS servers to: $($dnsServers -join ', ') on interface $($interface.InterfaceAlias)"
    Set-DnsClientServerAddress -InterfaceAlias $interface.InterfaceAlias -ServerAddresses $dnsServers
} else {
    Write-Host "No suitable network interface found to set DNS servers."
}

$computerSystem = Get-WmiObject Win32_ComputerSystem

if (-not ($computerSystem.PartOfDomain -and $computerSystem.Domain -ieq $domain)) {
    Write-Host "Retrieving Domain join username from SSM Parameter Store..."
	$username = (Get-SSMParameterValue -Name domainJoinUserUsername).Parameters[0].Value
	Write-Host "Domain join username: $username"

	Write-Host "Retrieving Domain join password from SSM Parameter Store with decryption..."
	$passwordPlainText = (Get-SSMParameterValue -Name domainJoinUserPassword -WithDecryption $True).Parameters[0].Value
	Write-Host "Password retrieved in plain text."

	# Convert to SecureString in-place (safe for any user context)
	$securePassword = ConvertTo-SecureString $passwordPlainText -AsPlainText -Force
	$credential = New-Object System.Management.Automation.PSCredential ("$username@$domain", $securePassword)


    Write-Host "Attempting to join the domain '$domain'..."
    Add-Computer -DomainName $domain -Credential $credential -Restart -Force
}
else {
    Write-Host "Machine is already joined to domain '$domain'. No action needed."
}

### Configure the SMB Drives

Write-Host "Retrieving FSx username from SSM Parameter Store..."
$username = (Get-SSMParameterValue -Name fsxUserUsername).Parameters[0].Value
Write-Host "FSx username: $username"

Write-Host "Retrieving FSx password from SSM Parameter Store with decryption..."
$password = (Get-SSMParameterValue -Name fsxUserPassword -WithDecryption $True).Parameters[0].Value | ConvertTo-SecureString -asPlainText -Force
Write-Host "FSx password retrieved and secured."

Write-Host "Creating PSCredential object from username and password..."
$credential = New-Object System.Management.Automation.PSCredential($username, $password)
Write-Host "PSCredential object created."

Write-Host "Mapping FSx share '\\amznfsxiw4hpd9j.bmo-aws-poc.virtusa.com\share\temp' to G: drive..."
New-SmbGlobalMapping -RemotePath '\\amznfsxiw4hpd9j.bmo-aws-poc.virtusa.com\share\temp' -Credential $credential -LocalPath G: -RequirePrivacy $true -ErrorAction Stop

Write-Host "Mapping FSx share '\\amznfsxiw4hpd9j.bmo-aws-poc.virtusa.com\share\IN' to H: drive..."
New-SmbGlobalMapping -RemotePath '\\amznfsxiw4hpd9j.bmo-aws-poc.virtusa.com\share\IN' -Credential $credential -LocalPath H: -RequirePrivacy $true -ErrorAction Stop


### Host name update

$prefix = "company-product-app-ec2-asg01-"
Write-Host "Using prefix: $prefix"

# Get metadata (IMDSv2 with fallback to IMDSv1)
Write-Host "Attempting to retrieve IMDSv2 token..."
$token = $null
try {
    $token = Invoke-RestMethod -Method PUT -Uri http://169.254.169.254/latest/api/token `
        -Headers @{ "X-aws-ec2-metadata-token-ttl-seconds" = "21600" } -ErrorAction Stop
    Write-Host "IMDSv2 token acquired."
} catch {
    Write-Host "IMDSv2 token acquisition failed. Falling back to IMDSv1."
}

$headers = @{}
if ($token) { $headers["X-aws-ec2-metadata-token"] = $token }

Write-Host "Fetching Instance ID..."
$instanceId = Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/instance-id -Headers $headers
Write-Host "Instance ID: $instanceId"

Write-Host "Fetching Region..."
$region = Invoke-RestMethod -Uri http://169.254.169.254/latest/dynamic/instance-identity/document -Headers $headers | Select-Object -ExpandProperty region
Write-Host "Region: $region"

Set-AWSCmdletContext -Region $region
Write-Host "AWS Cmdlet context set to region: $region"

# Get current instance Name tag
Write-Host "Getting current Name tag of the instance..."
$currentTags = (Get-EC2Instance -InstanceId $instanceId).Reservations.Instances.Tags
$currentName = ($currentTags | Where-Object { $_.Key -eq "Name" }).Value
Write-Host "Current Name tag: $currentName"

# Proceed only if the current name doesn't already match the desired prefix
if (-not ($currentName -like "$prefix*")) {
    Write-Host "Current Name does not match prefix. Proceeding to find next available name..."

    # Get all EC2 instances with names matching the prefix
    Write-Host "Fetching all EC2 instances with matching name prefix..."
    $allTags = Get-EC2Instance | Select-Object -ExpandProperty Instances | ForEach-Object {
        $_.Tags | Where-Object { $_.Key -eq "Name" -and $_.Value -like "$prefix*" }
    }

    # Extract existing numbers from matching names
    Write-Host "Extracting numeric suffixes from existing names..."
    $numbers = $allTags.Value | ForEach-Object {
        if ($_ -match [regex]::Escape($prefix) + "(\d{2})$") { [int]$matches[1] }
    } | Sort-Object -Descending

    $nextNum = if ($numbers.Count -eq 0) { 1 } else { $numbers[0] + 1 }
    $newName = "$prefix{0:D2}" -f $nextNum
    Write-Host "Next available number: $nextNum"
    Write-Host "New Name to assign: $newName"

    # Tag this instance with the new name
    Write-Host "Assigning new Name tag to instance..."
    New-EC2Tag -Resource $instanceId -Tags @{ Key = "Name"; Value = $newName }
    Write-Host "Name tag successfully updated to '$newName'."
} else {
    Write-Host "Current Name already matches prefix. No action needed."
}

### Configure ECS
$clusterName = "company-product-ec2ecs"

Write-Host "Checking if ECS Service is installed..."
$serviceExists = Get-Service -Name "AmazonECS" -ErrorAction SilentlyContinue

if ($serviceExists -and $env:ECS_CLUSTER -eq $clusterName) {
    Write-Host "ECS is already configured for cluster '$clusterName'. Skipping initialization."
} else {
    Write-Host "ECS not yet configured. Proceeding with initialization..."

    Write-Host "Importing ECSTools module..."
    Import-Module ECSTools

    Write-Host "Setting ECS_ENABLE_AWSLOGS_EXECUTIONROLE_OVERRIDE environment variable to TRUE..."
    [Environment]::SetEnvironmentVariable("ECS_ENABLE_AWSLOGS_EXECUTIONROLE_OVERRIDE", $TRUE, "Machine")

    Write-Host "Initializing ECS Agent for cluster '$clusterName' with IAM role, awslogs, task ENI, and blocking IMDS..."
    Initialize-ECSAgent -Cluster $clusterName -EnableTaskIAMRole -LoggingDrivers '["json-file","awslogs"]' -EnableTaskENI -AwsvpcBlockIMDS
}

# --- Cleanup ---

Write-Host "Removing scheduled task..."
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "Removing marker file..."
Remove-Item -Path $markerFile -Force -ErrorAction SilentlyContinue

Write-Host "Cleanup complete."

Write-Host "All operations completed. Stopping transcript logging."
Stop-Transcript
</powershell>

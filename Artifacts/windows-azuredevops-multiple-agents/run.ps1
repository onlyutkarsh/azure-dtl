# Downloads the Azure DevOps Pipelines Agent and installs specified instances on the new machine
# under C:\agents\ and registers with the Azure DevOps Pipelines agent pool

[CmdletBinding()]
Param
(
    [string]$Account,
    [string]$PersonalAccessToken,
    [string]$AgentName,
    [string]$AgentInstallLocation,
    [string]$PoolName,
    [int] $AgentCount,
    [bool] $Overwrite = $false,
    [string] $WindowsLogonAccount,
    [string] $WindowsLogonPassword,
    [bool] $runAsAutoLogon
)

###################################################################################################
#
# PowerShell configurations
#

# NOTE: Because the $ErrorActionPreference is "Stop", this script will stop on first failure.
#       This is necessary to ensure we capture errors inside the try-catch-finally block.
$ErrorActionPreference = "Stop"

# Suppress progress bar output.
$ProgressPreference = 'SilentlyContinue'

# Ensure we force use of TLS 1.2 for all downloads.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Configure strict debugging.
Set-PSDebug -Strict

# if the agentName is empty, use %COMPUTERNAME% as the value
if ([String]::IsNullOrWhiteSpace($agentName)) {
    $agentName = $env:COMPUTERNAME
}

# if the AgentInstallLocation is empty, use c:\agents as the value
if ([string]::IsNullOrWhiteSpace($AgentInstallLocation)) {
    $AgentInstallLocation = "c:\agents";
}

if ($AgentCount -le 0) {
    $AgentCount = 1;
}


###################################################################################################
#
# Handle all errors in this script.
#

trap {
    # NOTE: This trap will handle all errors. There should be no need to use a catch below in this
    #       script, unless you want to ignore a specific error.
    $message = $Error[0].Exception.Message
    if ($message) {
        Write-Host -Object "`nERROR: $message" -ForegroundColor Red
    }

    Write-Host "`nThe artifact failed to apply.`n"

    # IMPORTANT NOTE: Throwing a terminating error (using $ErrorActionPreference = "Stop") still
    # returns exit code zero from the PowerShell script when using -File. The workaround is to
    # NOT use -File when calling this script and leverage the try-catch-finally block and return
    # a non-zero exit code from the catch block.
    exit -1
}

###################################################################################################
#
# Functions
#

function Test-Parameters {
    [CmdletBinding()]
    param(
        [string] $Account,
        [string] $PersonalAccessToken,
        [string] $PoolName
    )

    if ([string]::IsNullOrWhiteSpace($Account)) {
        throw "Account parameter is required."
    }
    if ([string]::IsNullOrWhiteSpace($PersonalAccessToken)) {
        throw "PersonalAccessToken parameter is required."
    }
    if ([string]::IsNullOrWhiteSpace($PoolName)) {
        throw "PoolName parameter is required."
    }
}

function Test-ValidPath {
    param(
        [string] $Path
    )

    $isValid = Test-Path -Path $Path -IsValid -PathType Container

    try {
        [IO.Path]::GetFullPath($Path) | Out-Null
    }
    catch {
        $isValid = $false
    }

    return $isValid
}

function Test-AgentExists {
    [CmdletBinding()]
    param(
        [string] $InstallPath,
        [string] $AgentName
    )

    $agentConfigFile = Join-Path $InstallPath '.agent'

    if (Test-Path $agentConfigFile) {
        return $true
    }
    return $false
}

function Get-AgentPackage {
    [CmdletBinding()]
    param(
        [string] $VstsAccount,
        [string] $VstsUserPassword
    )

    # Create a temporary directory where to download from VSTS the agent package (agent.zip).
    $agentTempFolderName = Join-Path $env:temp ([System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Force -Path $agentTempFolderName | Out-Null

    $agentPackagePath = "$agentTempFolderName\agent.zip"
    $serverUrl = "https://$VstsAccount.visualstudio.com"
    $vstsAgentUrl = "$serverUrl/_apis/distributedtask/packages/agent/win7-x64?`$top=1&api-version=3.0"
    $vstsUser = "AzureDevTestLabs"

    $maxRetries = 3
    $retries = 0
    do {
        try {
            $basicAuth = ("{0}:{1}" -f $vstsUser, $vstsUserPassword)
            $basicAuth = [System.Text.Encoding]::UTF8.GetBytes($basicAuth)
            $basicAuth = [System.Convert]::ToBase64String($basicAuth)
            $headers = @{ Authorization = ("Basic {0}" -f $basicAuth) }

            $agentList = Invoke-RestMethod -Uri $vstsAgentUrl -Headers $headers -Method Get -ContentType application/json
            $agent = $agentList.value
            if ($agent -is [Array]) {
                $agent = $agentList.value[0]
            }
            Invoke-WebRequest -Uri $agent.downloadUrl -Headers $headers -Method Get -OutFile "$agentPackagePath" | Out-Null
            break
        }
        catch {
            $exceptionText = ($_ | Out-String).Trim()
                
            if (++$retries -gt $maxRetries) {
                throw "Failed to download agent due to $exceptionText"
            }
            
            Start-Sleep -Seconds 1 
        }
    }
    while ($retries -le $maxRetries)

    return $agentPackagePath
}


function New-AgentInstallPath {
    [CmdletBinding()]
    param(
        [string] $RootDirectory,
        [string] $AgentName
    )
    
    [string] $agentInstallPath = $null
    
    try {
        # Create the directory for this agent.
        $agentInstallPath = Join-Path -Path $RootDirectory -ChildPath $AgentName
        New-Item -ItemType Directory -Force -Path $agentInstallPath | Out-Null
    }
    catch {
        $agentInstallPath = $null
        throw "Failed to create the agent directory at $installPathDir."
    }
    
    return $agentInstallPath
}

function Get-AgentInstaller {
    param(
        [string] $InstallPath
    )

    $agentExePath = [System.IO.Path]::Combine($InstallPath, 'config.cmd')

    if (![System.IO.File]::Exists($agentExePath)) {
        throw "Agent installer file not found: $agentExePath"
    }
    
    return $agentExePath
}

function Extract-AgentPackage {
    [CmdletBinding()]
    param(
        [string] $PackagePath,
        [string] $Destination
    )
  
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($PackagePath)
    foreach ($entry in $archive.Entries) {
        $entryTargetFilePath = [System.IO.Path]::Combine($Destination, $entry.FullName)
        $entryDir = [System.IO.Path]::GetDirectoryName($entryTargetFilePath)
        
        #Ensure the directory of the archive entry exists
        if (!(Test-Path $entryDir )) {
            New-Item -ItemType Directory -Path $entryDir | Out-Null 
        }
        
        #If the entry is not a directory entry, then extract entry
        if (!$entryTargetFilePath.EndsWith("\")) {
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $entryTargetFilePath, $true);
        }
    }
}

function Prep-MachineForAutologon {
    param(
        $Config
    )

    if ([string]::IsNullOrWhiteSpace($Config.WindowsLogonPassword)) {
        throw "Windows logon password was not provided. Please retry by providing a valid windows logon password to enable autologon."
    }

    # Create a PS session for the user to trigger the creation of the registry entries required for autologon
    $computerName = "localhost"
    $password = ConvertTo-SecureString $Config.WindowsLogonPassword -AsPlainText -Force

    if ($Config.WindowsLogonAccount.Split("\").Count -eq 2) {
        $domain = $Config.WindowsLogonAccount.Split("\")[0]
        $userName = $Config.WindowsLogonAccount.Split('\')[1]
    }
    else {
        $domain = $Env:ComputerName
        $userName = $Config.WindowsLogonAccount
    }

    $credentials = New-Object System.Management.Automation.PSCredential("$domain\\$userName", $password)
    Enter-PSSession -ComputerName $computerName -Credential $credentials
    Exit-PSSession

    try {
        # Check if the HKU drive already exists
        Get-PSDrive -PSProvider Registry -Name HKU | Out-Null
        $canCheckRegistry = $true
    }
    catch [System.Management.Automation.DriveNotFoundException] {
        try {
            # Create the HKU drive
            New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
            $canCheckRegistry = $true
        }
        catch {
            # Ignore the failure to create the drive and go ahead with trying to set the agent up
            Write-Warning "Moving ahead with agent setup as the script failed to create HKU drive necessary for checking if the registry entry for the user's SId exists.\n$_"
        }
    }

    # 120 seconds timeout
    $timeout = 120

    # Check if the registry key required for enabling autologon is present on the machine, if not wait for 120 seconds in case the user profile is still getting created
    while ($timeout -ge 0 -and $canCheckRegistry) {
        $objUser = New-Object System.Security.Principal.NTAccount($Config.WindowsLogonAccount)
        $securityId = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
        $securityId = $securityId.Value

        if (Test-Path "HKU:\\$securityId") {
            if (!(Test-Path "HKU:\\$securityId\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")) {
                New-Item -Path "HKU:\\$securityId\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Force
                Write-Host "Created the registry entry path required to enable autologon."
            }
        
            break
        }
        else {
            $timeout -= 10
            Start-Sleep(10)
        }
    }

    if ($timeout -lt 0) {
        Write-Warning "Failed to find the registry entry for the SId of the user, this is required to enable autologon. Trying to start the agent anyway."
    }
}

function Install-Agent {
    param(
        $Config
    )

    try {
        # Set the current directory to the agent dedicated one previously created.
        Push-Location -Path $Config.AgentInstallPath

        

        if ($Config.RunAsAutoLogon) {
            Prep-MachineForAutologon -Config $Config

            # Arguements to run agent with autologon enabled
            $agentConfigArgs = "--unattended", "--url", $Config.ServerUrl, "--auth", "PAT", "--token", $Config.VstsUserPassword, "--pool", $Config.PoolName, "--agent", $Config.AgentName, "--runAsAutoLogon", "--overwriteAutoLogon", "--windowslogonaccount", $Config.WindowsLogonAccount
        }
        if (-not [string]::IsNullOrWhiteSpace($Config.WindowsLogonAccount)) {
            $agentConfigArgs = "--unattended", "--url", $Config.ServerUrl, "--auth", "PAT", "--token", $Config.VstsUserPassword, "--pool", $Config.PoolName, "--agent", $Config.AgentName, "--runasservice", "--windowslogonaccount", $Config.WindowsLogonAccount

            if (-not [string]::IsNullOrWhiteSpace($Config.WindowsLogonPassword)) {
                $agentConfigArgs += "--windowslogonpassword", $Config.WindowsLogonPassword
            }
        }
        else {
            # Arguements to run agent as a service
            $agentConfigArgs = "--unattended", "--url", $Config.ServerUrl, "--auth", "PAT", "--token", $Config.VstsUserPassword, "--pool", $Config.PoolName, "--agent", $Config.AgentName, "--runasservice"
        }
        
        # if ($Config.ReplaceAgent) {
        #     Write-Host "Removing agent"
        #     & $Config.AgentExePath $agentConfigArgs
        # }
        & $Config.AgentExePath $agentConfigArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Agent configuration failed for agent $($Config.AgentName) with exit code: $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}

function Remove-Agent {
    param(
        $Config
    )
    try {
        # Set the current directory to the agent dedicated one previously created.
        Push-Location -Path $Config.AgentInstallPath

        Write-Host "Removing agent '$($Config.AgentName)'"
        $agentConfigArgs = "remove", "--unattended", "--auth", "PAT", "--token", $Config.VstsUserPassword
        
        & $Config.AgentExePath $agentConfigArgs
    }
    finally {
        Pop-Location
    }
}


###################################################################################################
#
# Main execution block.
#
try {
    # Ensure we set the working directory to that of the script.
    Push-Location $PSScriptRoot

    Write-Output "Validating parameters..."

    Test-Parameters -Account $Account -PersonalAccessToken $PersonalAccessToken -PoolName $PoolName

    Write-Host 'Downloading agent package'
    $agentPackagePath = Get-AgentPackage -VstsAccount $Account -VstsUserPassword $PersonalAccessToken
        
    for ($i = 1; $i -lt $AgentCount + 1; $i++) {

        $updatedAgentName = ($AgentName + "-" + $i)

        Write-Host 'Preparing agent installation location'
        $agentInstallPath = New-AgentInstallPath -RootDirectory $AgentInstallLocation -AgentName $updatedAgentName

        Write-Host "Checking for previously configured agent with name '$updatedAgentName'"
        $agentExists = Test-AgentExists -InstallPath $agentInstallPath -AgentName $updatedAgentName

        if ($agentExists) {
            Write-Host "Getting agent installer path under '$agentInstallPath'"
            $agentExePath = Get-AgentInstaller -InstallPath $agentInstallPath
            
            if (!$Overwrite) {
                throw "Agent $updatedAgentName is already configured in this machine. Overwrite is false, so failing installation"
            }
            else {
                # if the agent is already running, you cannot just extract the zip. First uninstall and then copy.
                $config = @{
                    AgentName        = $updatedAgentName
                    AgentExePath     = $agentExePath
                    VstsUserPassword = $PersonalAccessToken
                }
                Remove-Agent -Config $config
            }
        }
        Write-Host "Extracting agent package contents to '$agentInstallPath'"
        Extract-AgentPackage -PackagePath $agentPackagePath -Destination $agentInstallPath

        Write-Host "Getting agent installer path under '$agentInstallPath'"
        $agentExePath = Get-AgentInstaller -InstallPath $agentInstallPath

        
        # Call the agent with the configure command and all the options (this creates the settings file)
        # without prompting the user or blocking the cmd execution.
        Write-Host "Installing agent $updatedAgentName under $agentInstallPath"
        $config = @{
            AgentExePath         = $agentExePath
            AgentInstallPath     = $agentInstallPath
            AgentName            = $updatedAgentName
            PoolName             = $poolName
            ReplaceAgent         = $Overwrite
            ServerUrl            = "https://$Account.visualstudio.com"
            VstsUserPassword     = $PersonalAccessToken
            WindowsLogonAccount  = $WindowsLogonAccount
            WindowsLogonPassword = $WindowsLogonPassword
            RunAsAutoLogon       = $runAsAutoLogon
        }
        Install-Agent -Config $config

    }
    Write-Host "`nThe artifact was applied successfully.`n"
}
finally {
    Pop-Location
}
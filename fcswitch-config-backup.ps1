<#
.SYNOPSIS
    FC Switch Configuration Backup - PowerShell Version
    Backs up Brocade FC switch configurations via REST API.

.DESCRIPTION
    Replicates fcswitch-config-backup.py using PowerShell for Brocade FOS REST API.
    Supports token-based and basic authentication, configuration retrieval, base64 decoding,
    logging, and error handling. Optimized for PowerShell 7.1+.

.AUTHOR
    Adapted from Python script by Pre-Sales Systems Engineer

.VERSION
    1.9

.EXAMPLE
    .\fcswitch-config-backup.ps1 -IP 192.168.1.100 -Username admin
    .\fcswitch-config-backup.ps1 -IP 10.124.5.33 -Username admin -VerifySSL
    .\fcswitch-config-backup.ps1 -IP 10.124.5.33 -Username admin -OutputFile my_config.txt -Debug
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Switch IP address")]
    [string]$IP,

    [Parameter(Mandatory = $true, HelpMessage = "Switch username (typically 'admin')")]
    [string]$Username,

    [Parameter(Mandatory = $false, HelpMessage = "Output filename (default: auto-generated with timestamp)")]
    [string]$OutputFile,

    [Parameter(Mandatory = $false, HelpMessage = "Verify SSL certificates")]
    [switch]$VerifySSL
)

# Script variables
$LogFile = "fcswitch_config_backup.log"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BaseUrl = "https://$IP/rest"
$AuthToken = $null
$LastError = $null

# Logging function
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $logTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$logTimestamp - $Level - $Message"

    # Write to log file
    Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8

    # Write to console if level is appropriate
    if ($Level -eq "DEBUG" -and $DebugPreference -eq "SilentlyContinue") {
        return
    }
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        default { Write-Host $logEntry }
    }
}

# Initialize logging
Write-Log -Level "INFO" -Message ("=" * 60)
Write-Log -Level "INFO" -Message "FC Switch Configuration Backup Tool - PowerShell Version"
Write-Log -Level "INFO" -Message ("=" * 60)
Write-Log -Level "INFO" -Message "Target switch: $IP"
Write-Log -Level "INFO" -Message "Username: $Username"
Write-Log -Level "INFO" -Message "SSL verification: $VerifySSL"

# Prompt for password securely
$SecurePassword = Read-Host -Prompt "Password for $Username@$IP" -AsSecureString
$Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
)

# Function to authenticate with token
function Connect-TokenAuth {
    Write-Log -Level "INFO" -Message "Attempting token-based authentication"
    $loginUrl = "$BaseUrl/login"
    $headers = @{
        "Accept" = "application/yang-data+json"
        "Content-Type" = "application/yang-data+json"
    }
    $authString = "${Username}:${Password}"
    $creds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($authString))
    $authHeader = @{ "Authorization" = "Basic $creds" }

    try {
        $response = Invoke-WebRequest -Uri $loginUrl -Method Post -Headers ($headers + $authHeader) `
            -TimeoutSec 10 -SkipCertificateCheck:(-not $VerifySSL)
        Write-Log -Level "DEBUG" -Message "Login response status: $($response.StatusCode)"
        Write-Log -Level "DEBUG" -Message "Response headers: $($response.Headers | ConvertTo-Json)"

        # Extract token case-insensitively
        $token = $response.Headers.GetEnumerator() | Where-Object { $_.Key -ieq "Authorization" } | Select-Object -ExpandProperty Value
        if ($token) {
            Write-Log -Level "INFO" -Message "Successfully authenticated using token method"
            Write-Log -Level "DEBUG" -Message "Authorization token received: $($token.Substring(0, [Math]::Min(20, $token.Length)))..."
            return $token
        } else {
            Write-Log -Level "WARNING" -Message "Login succeeded but no Authorization token received"
            return $null
        }
    } catch {
        Write-Log -Level "DEBUG" -Message "Token authentication failed: $($_.Exception.Message)"
        Write-Log -Level "DEBUG" -Message "Exception details: $($_.Exception | Format-List -Property * | Out-String)"
        return $null
    }
}

# Function to test basic authentication
function Test-BasicAuth {
    Write-Log -Level "INFO" -Message "Testing basic authentication"
    $testUrl = "$BaseUrl/running/brocade-fibrechannel-switch/fibrechannel-switch"
    $headers = @{
        "Accept" = "application/yang-data+json"
        "Authorization" = "Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${Username}:${Password}"))
    }

    try {
        $response = Invoke-WebRequest -Uri $testUrl -Method Get -Headers $headers `
            -TimeoutSec 10 -SkipCertificateCheck:(-not $VerifySSL)
        Write-Log -Level "INFO" -Message "Successfully authenticated using basic authentication"
        Write-Log -Level "DEBUG" -Message "Basic auth response status: $($response.StatusCode)"
        return $true
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.Value__ ?? "Unknown"
        $LastError = switch ($statusCode) {
            403 { "Access denied - check user permissions (admin role required)" }
            401 { "Authentication failed - invalid credentials" }
            default { "Basic authentication test failed: HTTP $statusCode - $($_.Exception.Message)" }
        }
        Write-Log -Level "ERROR" -Message $LastError
        Write-Log -Level "DEBUG" -Message "Exception details: $($_.Exception | Format-List -Property * | Out-String)"
        return $false
    }
}

# Function to backup configuration
function Backup-Configuration {
    param (
        [string]$Token
    )

    Write-Log -Level "INFO" -Message "Starting configuration backup"
    $backupUrl = "$BaseUrl/operations/configupload"
    $headers = @{
        "Accept" = "application/yang-data+json"
        "Content-Type" = "application/yang-data+json"
    }
    $body = @{
        "configupload-parameters" = @{
            "config-upload-download-option" = "all"
            "port-to-area" = $false
        }
    } | ConvertTo-Json

    try {
        if ($Token) {
            $headers["Authorization"] = $Token
            $response = Invoke-RestMethod -Uri $backupUrl -Method Post -Headers $headers `
                -Body $body -TimeoutSec 60 -SkipCertificateCheck:(-not $VerifySSL)
        } else {
            $headers["Authorization"] = "Basic " + [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("${Username}:${Password}"))
            $response = Invoke-RestMethod -Uri $backupUrl -Method Post -Headers $headers `
                -Body $body -TimeoutSec 60 -SkipCertificateCheck:(-not $VerifySSL)
        }

        Write-Log -Level "INFO" -Message "Configupload response status: 200"
        Write-Log -Level "DEBUG" -Message "Response content: $($response | ConvertTo-Json -Depth 3)"
        return Process-BackupResponse -Response $response
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.Value__ ?? "Unknown"
        $errorMsg = switch ($statusCode) {
            403 { "Access denied - check user permissions (admin role required)" }
            401 { "Authentication failed - check credentials" }
            default {
                try {
                    $errorData = $_.Exception.Response.Content | ConvertFrom-Json
                    $apiError = $errorData.errors.error[0].'error-message' ?? "Unknown API error"
                    "HTTP $statusCode - $apiError"
                } catch {
                    "HTTP $statusCode - $($_.Exception.Message)"
                }
            }
        }
        Write-Log -Level "ERROR" -Message "Configuration backup failed: $errorMsg"
        Write-Log -Level "DEBUG" -Message "Exception details: $($_.Exception | Format-List -Property * | Out-String)"
        return $false, $errorMsg, "", ""
    }
}

# Function to process backup response
function Process-BackupResponse {
    param (
        [Parameter(Mandatory = $true)]
        $Response
    )

    Write-Log -Level "DEBUG" -Message "Response keys: $($Response.PSObject.Properties.Name -join ', ')"

    if ($Response.Response.'configupload-operation-status') {
        $statusInfo = $Response.Response.'configupload-operation-status'
        $configData = $statusInfo.'config-output-buffer'
        $statusMessage = $statusInfo.'status-message' ?? "No status message"

        Write-Log -Level "INFO" -Message "Operation status: $statusMessage"

        if ($configData) {
            $rawB64Data = $configData
            $decodedConfig = Decode-ConfigurationData -ConfigData $configData
            if ($decodedConfig) {
                $configSize = $decodedConfig.Length
                Write-Log -Level "INFO" -Message "Successfully retrieved configuration ($($configSize.ToString('N0')) characters)"
                return $true, "Configuration retrieved successfully", $decodedConfig, $rawB64Data
            } else {
                return $false, "Failed to decode configuration data", "", ""
            }
        } else {
            return $false, "No configuration data in response: $statusMessage", "", ""
        }
    } else {
        Write-Log -Level "WARNING" -Message "Unexpected response structure"
        return $false, "Unexpected response format from switch", "", ""
    }
}

# Function to decode configuration data
function Decode-ConfigurationData {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConfigData
    )

    if (-not $ConfigData) {
        return ""
    }

    Write-Log -Level "DEBUG" -Message "Raw config data length: $($ConfigData.Length)"
    Write-Log -Level "DEBUG" -Message "First 100 chars: $($ConfigData.Substring(0, [Math]::Min(100, $ConfigData.Length)))"

    try {
        $decodedBytes = [System.Convert]::FromBase64String($ConfigData)
        $decodedString = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
        Write-Log -Level "INFO" -Message "Successfully decoded base64 configuration data"
        Write-Log -Level "DEBUG" -Message "Decoded config first 100 chars: $($decodedString.Substring(0, [Math]::Min(100, $decodedString.Length)))"
        return $decodedString
    } catch {
        Write-Log -Level "WARNING" -Message "Base64 decode failed: $($_.Exception.Message)"
        if ($ConfigData -match 'switch|zone|alias|cfg|configuration') {
            Write-Log -Level "INFO" -Message "Data appears to be already in text format"
            return $ConfigData
        } else {
            Write-Log -Level "WARNING" -Message "Unknown configuration data format"
            return ""
        }
    }
}

# Function to save configuration files
function Save-ConfigurationFiles {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConfigData,

        [Parameter(Mandatory = $true)]
        [string]$RawB64Data,

        [Parameter(Mandatory = $true)]
        [string]$SwitchIP,

        [string]$OutputFile
    )

    $cleanIP = $SwitchIP -replace '\.', '_'
    $fileBase = if ($OutputFile) {
        [System.IO.Path]::GetFileNameWithoutExtension($OutputFile)
    } else {
        "fc_switch_config_${cleanIP}_${Timestamp}"
    }

    $txtFile = "$fileBase.txt"
    $b64File = "$fileBase.b64"

    try {
        Set-Content -Path $txtFile -Value $ConfigData -Encoding UTF8
        Set-Content -Path $b64File -Value $RawB64Data -Encoding UTF8
        return $txtFile, $b64File
    } catch {
        throw "Failed to save configuration files: $($_.Exception.Message)"
    }
}

# Function to disconnect
function Disconnect {
    if (-not $AuthToken) {
        Write-Log -Level "INFO" -Message "No token-based session to logout"
        return
    }

    $logoutUrl = "$BaseUrl/logout"
    $headers = @{
        "Authorization" = $AuthToken
        "Accept" = "application/yang-data+json"
        "Content-Type" = "application/yang-data+json"
    }

    try {
        Write-Log -Level "DEBUG" -Message "Sending logout request to $logoutUrl with headers: $($headers | ConvertTo-Json)"
        $response = Invoke-WebRequest -Uri $logoutUrl -Method Post -Headers $headers `
            -TimeoutSec 5 -SkipCertificateCheck:(-not $VerifySSL)
        Write-Log -Level "INFO" -Message "Successfully logged out from switch (Status: $($response.StatusCode))"
        Write-Log -Level "DEBUG" -Message "Logout response headers: $($response.Headers | ConvertTo-Json)"
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.Value__ ?? "Unknown"
        Write-Log -Level "WARNING" -Message "Logout error (non-critical): HTTP $statusCode - $($_.Exception.Message)"
        Write-Log -Level "DEBUG" -Message "Logout exception details: $($_.Exception | Format-List -Property * | Out-String)"
    }
}

# Main script
try {
    # Step 1: Connect
    Write-Log -Level "INFO" -Message "Step 1: Connecting to switch"
    $AuthToken = Connect-TokenAuth
    if (-not $AuthToken) {
        if (-not (Test-BasicAuth)) {
            Write-Log -Level "ERROR" -Message "Failed to connect: $LastError"
            exit 1
        }
    }

    # Step 2: Backup configuration
    Write-Log -Level "INFO" -Message "Step 2: Retrieving configuration"
    $success, $message, $configData, $rawB64Data = Backup-Configuration -Token $AuthToken
    if (-not $success) {
        Write-Log -Level "ERROR" -Message "Configuration backup failed: $message"
        exit 1
    }

    # Step 3: Save configuration
    Write-Log -Level "INFO" -Message "Step 3: Saving configuration files"
    try {
        $txtFile, $b64File = Save-ConfigurationFiles -ConfigData $configData -RawB64Data $rawB64Data -SwitchIP $IP -OutputFile $OutputFile
        Write-Log -Level "INFO" -Message "Text configuration saved to: $txtFile"
        Write-Log -Level "INFO" -Message "Base64 configuration saved to: $b64File"

        # Print summary
        $configSize = $configData.Length
        $b64Size = $rawB64Data.Length
        $lineCount = ($configData -split "`n").Count

        $summary = @"
============================================================
BACKUP COMPLETED SUCCESSFULLY
============================================================
Switch IP:          $IP
Text file:          $txtFile
Base64 file:        $b64File
Configuration size: $($configSize.ToString('N0')) characters
Base64 size:        $($b64Size.ToString('N0')) characters
Lines:              $($lineCount.ToString('N0'))
============================================================
NOTE: Keep both files for complete backup!
  • .txt file: Human-readable for review/troubleshooting
  • .b64 file: Ready for configdownload restore operations
============================================================
"@
        Write-Host $summary
        Write-Log -Level "INFO" -Message "Backup summary displayed"
    } catch {
        Write-Log -Level "ERROR" -Message "Failed to save configuration files: $($_.Exception.Message)"
        exit 1
    }
} finally {
    # Step 4: Disconnect
    Write-Log -Level "INFO" -Message "Step 4: Disconnecting"
    Disconnect
    Write-Log -Level "INFO" -Message "Backup process completed"
}

exit 0
# B-type FC Switch Configuration Backup (PowerShell)

This PowerShell script, `fcswitch-config-backup.ps1`, automates the backup of Brocade Fibre Channel (FC) switch configurations using the Brocade Fabric OS (FOS) REST API. It provides a robust solution for Windows environments running PowerShell 7.1 or later. The script authenticates with the switch, retrieves the configuration, decodes base64-encoded data, saves both text and base64 output files, and logs out cleanly.

## Features
- Supports token-based and basic authentication.
- Retrieves switch configuration via the FOS REST API (`/rest/operations/configupload`).
- Saves human-readable (`.txt`) and base64 (`.b64`) configuration files.
- Comprehensive logging for debugging and monitoring.
- Handles SSL verification (optional) and error conditions gracefully.
- Compatible with Brocade FOS v9.2.1a and later.

## Requirements
- **PowerShell**: Version 7.1 or later.
- **Operating System**: Windows (or any OS supporting PowerShell 7.1+).
- **Network Access**: Connectivity to the Brocade FC switch over HTTPS (port 443).
- **Credentials**: Administrative username and password for the switch.
- **Execution Policy**: Set to `RemoteSigned` or `Bypass` (run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`).

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/<your-username>/fcswitch-config-backup-powershell.git
   cd fcswitch-config-backup-powershell
   ```

2. **Ensure PowerShell 7.1+**:
   Verify your PowerShell version:
   ```powershell
   $PSVersionTable.PSVersion
   ```
   If needed, install PowerShell 7.1+ from [Microsoft's PowerShell GitHub](https://github.com/PowerShell/PowerShell/releases).

3. **Set Execution Policy** (if not already set):
   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
   ```

## Usage
Run the script from the command line, specifying the switch IP and username. The script prompts for the password securely.

```powershell
.\fcswitch-config-backup.ps1 -IP <switch-ip> -Username <username> [-OutputFile <filename>] [-VerifySSL] [-Debug]
```

### Parameters
- `-IP` (required): The IP address of the Brocade FC switch (e.g., `192.168.1.100`).
- `-Username` (required): The switch username (typically `admin`).
- `-OutputFile` (optional): Custom base name for output files (default: `fc_switch_config_<ip>_<timestamp>`).
- `-VerifySSL` (optional): Enable SSL certificate verification (default: disabled).
- `-Debug` (optional): Enable verbose logging for troubleshooting.

### Output
- **Text File**: Human-readable configuration (e.g., `fc_switch_config_192_168_1_100_20250705_094500.txt`).
- **Base64 File**: Raw base64 configuration for restores (e.g., `fc_switch_config_192_168_1_100_20250705_094500.b64`).
- **Log File**: Detailed execution log (`fcswitch_config_backup.log`).

## Examples
1. **Basic Backup**:
   ```powershell
   .\fcswitch-config-backup.ps1 -IP 192.168.1.100 -Username admin
   ```
   Prompts for password and saves config files in the current directory.

2. **Custom Output File with SSL Verification**:
   ```powershell
   .\fcswitch-config-backup.ps1 -IP 192.168.1.100 -Username admin -OutputFile my_config -VerifySSL
   ```
   Saves `my_config.txt` and `my_config.b64`.

3. **Debug Mode**:
   ```powershell
   .\fcswitch-config-backup.ps1 -IP 192.168.1.100 -Username admin -Debug
   ```
   Logs detailed debugging info to `fcswitch_config_backup.log`.

4. **Scheduled Backup**:
   Schedule daily backups using Task Scheduler:
   ```powershell
   $action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-File C:\path\to\fcswitch-config-backup.ps1 -IP 192.168.1.100 -Username admin"
   $trigger = New-ScheduledTaskTrigger -Daily -At "2:00AM"
   Register-ScheduledTask -TaskName "FCSwitchBackup" -Action $action -Trigger $trigger -Description "Daily FC switch config backup"
   ```
   Note: Store the password securely (e.g., using a credential manager).

## Troubleshooting
- **HTTP 415 (Unsupported Media Type)**:
  - Ensure the logout request uses `Accept: application/yang-data+json` and `Content-Type: application/yang-data+json`.
  - Check the log (`fcswitch_config_backup.log`) for `Logout exception details`.
- **Authentication Errors**:
  - Verify the username and password.
  - Check switch permissions (admin role required).
  - Run `restconfig --show` on the switch to confirm `http.enabled:1` and `http.ssl.enabled:1`.
- **Session Limits**:
  - The switch limits REST sessions (`http.maxrestsession:10`). To manage sessions:
    1. Log in to the switch via SSH (FOS CLI):
       ```bash
       ssh admin@192.168.1.100
       ```
    2. List active REST sessions:
       ```bash
       mgmtapp --showsessions
       ```
    3. Terminate a specific session if needed:
       ```bash
       mgmtapp --terminate <session_id>
       ```
    See [Brocade FOS Command Reference](https://techdocs.broadcom.com/us/en/fibre-channel-networking/fabric-os/fabric-os-commands/9-2-x/Fabric-OS-Commands/mgmtApp_922.html) for details.
- **Verbose Logging**:
  - Use `-Debug` to capture detailed logs:
    ```powershell
    .\fcswitch-config-backup.ps1 -IP 192.168.1.100 -Username admin -Debug
    ```

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

Please include:
- Detailed descriptions of changes.
- Tests to verify functionality.
- Updates to this README if new features are added.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments
- Thanks to the [Brocade Fabric OS REST API Reference Manual](https://docs.broadcom.com/docs/fabric-os-rest-api) for detailed endpoint specifications.
- Special shoutout to the community for debugging insights on HTTP 415 errors.

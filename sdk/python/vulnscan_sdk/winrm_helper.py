"""
WinRM Helper for Plugins

Provides WinRM connection utilities for Windows plugins that need remote access.
"""
import logging
from typing import Optional, Tuple
import base64

try:
    from winrm.protocol import Protocol
    from winrm import Session
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False
    logging.warning("pywinrm not installed - Windows plugins will not work")


class WinRMConnectionError(Exception):
    """WinRM connection failed"""
    pass


class WinRMExecutionError(Exception):
    """WinRM command execution failed"""
    pass


class WinRMHelper:
    """
    Helper class for WinRM connections in Windows plugins.

    Handles WinRM authentication and PowerShell/CMD command execution.
    Requires pywinrm package: pip install pywinrm
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize WinRM helper.

        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger("winrm_helper")
        self.session: Optional[Session] = None
        self.connected = False
        self.endpoint = None

        if not WINRM_AVAILABLE:
            self.logger.error("pywinrm package not available")

    def connect(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 5985,
        transport: str = "ntlm",
        use_ssl: bool = False,
        timeout: int = 30
    ) -> bool:
        """
        Connect to WinRM server.

        Args:
            host: Hostname or IP address
            username: Windows username (domain\\user or user@domain or user)
            password: Windows password
            port: WinRM port (5985 for HTTP, 5986 for HTTPS)
            transport: Authentication transport ('ntlm', 'kerberos', 'basic')
            use_ssl: Use HTTPS (port 5986)
            timeout: Connection timeout in seconds

        Returns:
            True if connected successfully

        Raises:
            WinRMConnectionError: If connection fails
        """
        if not WINRM_AVAILABLE:
            raise WinRMConnectionError("pywinrm package not installed")

        try:
            # Build endpoint URL
            protocol = "https" if use_ssl else "http"
            self.endpoint = f"{protocol}://{host}:{port}/wsman"

            self.logger.info(f"Connecting to {self.endpoint} as {username}")

            # Create WinRM session
            self.session = Session(
                self.endpoint,
                auth=(username, password),
                transport=transport,
                server_cert_validation='ignore' if use_ssl else None,
                read_timeout_sec=timeout,
                operation_timeout_sec=timeout
            )

            # Test connection with simple command
            result = self.session.run_cmd('echo', ['test'])

            if result.status_code == 0:
                self.connected = True
                self.logger.info("WinRM connection established successfully")
                return True
            else:
                raise WinRMConnectionError(f"Connection test failed with status {result.status_code}")

        except Exception as e:
            self.logger.error(f"WinRM connection error: {e}")
            raise WinRMConnectionError(f"Connection error: {e}")

    def execute_command(
        self,
        command: str,
        timeout: int = 300,
        check_exit_code: bool = True,
        use_powershell: bool = False
    ) -> Tuple[int, str, str]:
        """
        Execute a command over WinRM.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds
            check_exit_code: Raise exception if exit code != 0
            use_powershell: Use PowerShell instead of CMD

        Returns:
            Tuple of (exit_code, stdout, stderr)

        Raises:
            WinRMExecutionError: If command fails and check_exit_code=True
        """
        if not self.connected or not self.session:
            raise WinRMExecutionError("Not connected to WinRM server")

        try:
            self.logger.debug(f"Executing command: {command}")

            # Execute command
            if use_powershell:
                result = self.session.run_ps(command)
            else:
                # For CMD commands, need to parse properly
                if ' ' in command:
                    parts = command.split(' ', 1)
                    cmd = parts[0]
                    args = [parts[1]] if len(parts) > 1 else []
                else:
                    cmd = command
                    args = []
                result = self.session.run_cmd(cmd, args)

            exit_code = result.status_code
            stdout = result.std_out.decode('utf-8', errors='replace') if result.std_out else ""
            stderr = result.std_err.decode('utf-8', errors='replace') if result.std_err else ""

            self.logger.debug(f"Command completed with exit code: {exit_code}")

            if check_exit_code and exit_code != 0:
                raise WinRMExecutionError(
                    f"Command failed with exit code {exit_code}\n"
                    f"STDOUT: {stdout}\n"
                    f"STDERR: {stderr}"
                )

            return exit_code, stdout, stderr

        except WinRMExecutionError:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during command execution: {e}")
            raise WinRMExecutionError(f"Execution error: {e}")

    def execute_powershell(
        self,
        script: str,
        timeout: int = 300,
        check_exit_code: bool = True
    ) -> Tuple[int, str, str]:
        """
        Execute a PowerShell script over WinRM.

        Args:
            script: PowerShell script to execute
            timeout: Script timeout in seconds
            check_exit_code: Raise exception if exit code != 0

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        return self.execute_command(script, timeout, check_exit_code, use_powershell=True)

    def test_admin_access(self) -> bool:
        """
        Test if current user has administrative privileges.

        Returns:
            True if user is admin
        """
        try:
            exit_code, stdout, _ = self.execute_powershell(
                "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
                check_exit_code=False
            )
            return exit_code == 0 and 'True' in stdout
        except:
            return False

    def get_system_info(self) -> dict:
        """
        Get basic Windows system information.

        Returns:
            Dictionary with system info
        """
        try:
            # Get computer name
            _, hostname, _ = self.execute_command("hostname", check_exit_code=False)

            # Get OS info via PowerShell
            _, os_info, _ = self.execute_powershell(
                "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | ConvertTo-Json",
                check_exit_code=False
            )

            return {
                'hostname': hostname.strip(),
                'os_info': os_info.strip(),
                'is_admin': self.test_admin_access()
            }
        except Exception as e:
            self.logger.error(f"Failed to get system info: {e}")
            return {}

    def disconnect(self):
        """Close WinRM connection."""
        if self.session:
            # WinRM Session doesn't need explicit close in pywinrm
            self.session = None
            self.connected = False
            self.logger.info("WinRM connection closed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures connection is closed."""
        self.disconnect()

    def __del__(self):
        """Cleanup - close connection if still open."""
        if self.connected:
            self.disconnect()

"""
SSH Helper for Plugins

Provides SSH connection utilities for plugins that need remote access.
"""
import paramiko
import logging
from typing import Optional, Dict, Any, Tuple
from io import StringIO
import time


class SSHConnectionError(Exception):
    """SSH connection failed"""
    pass


class SSHExecutionError(Exception):
    """SSH command execution failed"""
    pass


class SSHHelper:
    """
    Helper class for SSH connections in plugins.

    Handles SSH authentication (password or key-based) and command execution.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize SSH helper.

        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger("ssh_helper")
        self.client: Optional[paramiko.SSHClient] = None
        self.connected = False

    def connect(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        port: int = 22,
        timeout: int = 30
    ) -> bool:
        """
        Connect to SSH server.

        Args:
            host: Hostname or IP address
            username: SSH username
            password: SSH password (if password auth)
            private_key: Private key string (if key auth)
            port: SSH port (default 22)
            timeout: Connection timeout in seconds

        Returns:
            True if connected successfully

        Raises:
            SSHConnectionError: If connection fails
        """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": host,
                "port": port,
                "username": username,
                "timeout": timeout,
                "look_for_keys": False,
                "allow_agent": False
            }

            # Use private key if provided
            if private_key:
                self.logger.debug("Using SSH key authentication")
                key_file = StringIO(private_key)
                pkey = paramiko.RSAKey.from_private_key(key_file)
                connect_kwargs["pkey"] = pkey
            elif password:
                self.logger.debug("Using password authentication")
                connect_kwargs["password"] = password
            else:
                raise SSHConnectionError("No authentication method provided (password or private key required)")

            self.logger.info(f"Connecting to {host}:{port} as {username}")
            self.client.connect(**connect_kwargs)

            self.connected = True
            self.logger.info("SSH connection established successfully")
            return True

        except paramiko.AuthenticationException as e:
            self.logger.error(f"SSH authentication failed: {e}")
            raise SSHConnectionError(f"Authentication failed: {e}")
        except paramiko.SSHException as e:
            self.logger.error(f"SSH connection error: {e}")
            raise SSHConnectionError(f"SSH error: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during SSH connection: {e}")
            raise SSHConnectionError(f"Connection error: {e}")

    def execute_command(
        self,
        command: str,
        timeout: int = 300,
        check_exit_code: bool = True
    ) -> Tuple[int, str, str]:
        """
        Execute a command over SSH.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds
            check_exit_code: Raise exception if exit code != 0

        Returns:
            Tuple of (exit_code, stdout, stderr)

        Raises:
            SSHExecutionError: If command fails and check_exit_code=True
        """
        if not self.connected or not self.client:
            raise SSHExecutionError("Not connected to SSH server")

        try:
            self.logger.debug(f"Executing command: {command}")

            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)

            # Wait for command to complete
            exit_code = stdout.channel.recv_exit_status()

            # Read output
            stdout_str = stdout.read().decode('utf-8', errors='replace')
            stderr_str = stderr.read().decode('utf-8', errors='replace')

            self.logger.debug(f"Command completed with exit code: {exit_code}")

            if check_exit_code and exit_code != 0:
                raise SSHExecutionError(
                    f"Command failed with exit code {exit_code}\n"
                    f"STDOUT: {stdout_str}\n"
                    f"STDERR: {stderr_str}"
                )

            return exit_code, stdout_str, stderr_str

        except paramiko.SSHException as e:
            self.logger.error(f"SSH execution error: {e}")
            raise SSHExecutionError(f"Execution error: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during command execution: {e}")
            raise SSHExecutionError(f"Execution error: {e}")

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """
        Upload a file via SFTP.

        Args:
            local_path: Local file path
            remote_path: Remote file path

        Returns:
            True if successful

        Raises:
            SSHExecutionError: If upload fails
        """
        if not self.connected or not self.client:
            raise SSHExecutionError("Not connected to SSH server")

        try:
            sftp = self.client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            self.logger.info(f"Uploaded {local_path} to {remote_path}")
            return True
        except Exception as e:
            self.logger.error(f"File upload failed: {e}")
            raise SSHExecutionError(f"Upload error: {e}")

    def download_file(self, remote_path: str, local_path: str) -> bool:
        """
        Download a file via SFTP.

        Args:
            remote_path: Remote file path
            local_path: Local file path

        Returns:
            True if successful

        Raises:
            SSHExecutionError: If download fails
        """
        if not self.connected or not self.client:
            raise SSHExecutionError("Not connected to SSH server")

        try:
            sftp = self.client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            self.logger.info(f"Downloaded {remote_path} to {local_path}")
            return True
        except Exception as e:
            self.logger.error(f"File download failed: {e}")
            raise SSHExecutionError(f"Download error: {e}")

    def disconnect(self):
        """Close SSH connection."""
        if self.client:
            self.client.close()
            self.connected = False
            self.logger.info("SSH connection closed")

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

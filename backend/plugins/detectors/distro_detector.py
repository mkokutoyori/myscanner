"""
Linux Distribution Detector

Automatically detects Linux distribution and version to enable
distribution-specific vulnerability scanning.

Based on research from LINUX_SECURITY_RESEARCH.md
"""
import logging
import re
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class DistroFamily(Enum):
    """Linux distribution families"""
    DEBIAN = "debian"
    REDHAT = "redhat"
    SUSE = "suse"
    ARCH = "arch"
    ALPINE = "alpine"
    UNKNOWN = "unknown"


@dataclass
class DistroInfo:
    """Linux distribution information"""
    family: DistroFamily
    name: str
    version: str
    version_codename: Optional[str] = None
    id: Optional[str] = None
    id_like: Optional[str] = None
    package_manager: Optional[str] = None

    # Security-related attributes
    mac_system: Optional[str] = None  # SELinux, AppArmor, etc.
    firewall: Optional[str] = None  # firewalld, ufw, iptables
    init_system: Optional[str] = None  # systemd, sysvinit

    # Raw os-release data
    raw_data: Optional[Dict[str, str]] = None


class DistroDetector:
    """
    Detects Linux distribution information via SSH.

    Uses /etc/os-release as primary method (systemd standard).
    Falls back to legacy methods for older systems.
    """

    def __init__(self, ssh_helper):
        """
        Initialize detector with SSH connection.

        Args:
            ssh_helper: SSHHelper instance (must be connected)
        """
        self.ssh = ssh_helper
        self.logger = logging.getLogger(__name__)

    def detect(self) -> DistroInfo:
        """
        Detect Linux distribution information.

        Returns:
            DistroInfo object with detected information
        """
        self.logger.info("Detecting Linux distribution...")

        # Try modern method: /etc/os-release
        distro_info = self._detect_from_os_release()

        if distro_info.family == DistroFamily.UNKNOWN:
            # Fallback to legacy methods
            self.logger.warning("os-release not found, trying legacy detection")
            distro_info = self._detect_legacy()

        # Detect additional system info
        self._detect_package_manager(distro_info)
        self._detect_mac_system(distro_info)
        self._detect_firewall(distro_info)
        self._detect_init_system(distro_info)

        self.logger.info(
            f"Detected: {distro_info.name} {distro_info.version} "
            f"(Family: {distro_info.family.value})"
        )

        return distro_info

    def _detect_from_os_release(self) -> DistroInfo:
        """
        Detect distribution from /etc/os-release.

        This is the modern standard method (systemd).
        Format documented at: https://www.freedesktop.org/software/systemd/man/os-release.html

        Returns:
            DistroInfo object
        """
        exit_code, output, _ = self.ssh.execute_command(
            "cat /etc/os-release",
            check_exit_code=False
        )

        if exit_code != 0:
            self.logger.warning("/etc/os-release not found")
            return DistroInfo(
                family=DistroFamily.UNKNOWN,
                name="Unknown",
                version="Unknown"
            )

        # Parse os-release file
        os_release = self._parse_os_release(output)

        # Extract key fields
        distro_id = os_release.get('ID', '').lower()
        distro_name = os_release.get('NAME', os_release.get('PRETTY_NAME', 'Unknown'))
        distro_version = os_release.get('VERSION_ID', os_release.get('VERSION', 'Unknown'))
        version_codename = os_release.get('VERSION_CODENAME')
        id_like = os_release.get('ID_LIKE', '')

        # Determine distribution family
        family = self._determine_family(distro_id, id_like)

        return DistroInfo(
            family=family,
            name=distro_name,
            version=distro_version,
            version_codename=version_codename,
            id=distro_id,
            id_like=id_like,
            raw_data=os_release
        )

    def _parse_os_release(self, content: str) -> Dict[str, str]:
        """
        Parse /etc/os-release content.

        Format:
            KEY="value"
            KEY=value

        Args:
            content: File content

        Returns:
            Dictionary of key-value pairs
        """
        result = {}

        for line in content.split('\n'):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Parse KEY=VALUE
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                result[key] = value

        return result

    def _determine_family(self, distro_id: str, id_like: str) -> DistroFamily:
        """
        Determine distribution family from ID and ID_LIKE.

        Args:
            distro_id: Distribution ID (e.g., "ubuntu")
            id_like: Space-separated list of related distributions

        Returns:
            DistroFamily enum value
        """
        # Combine ID and ID_LIKE for matching
        all_ids = f"{distro_id} {id_like}".lower()

        # Debian family
        if any(x in all_ids for x in ['debian', 'ubuntu', 'mint', 'kali', 'raspbian']):
            return DistroFamily.DEBIAN

        # Red Hat family
        if any(x in all_ids for x in ['rhel', 'redhat', 'centos', 'fedora', 'rocky', 'alma', 'oracle']):
            return DistroFamily.REDHAT

        # SUSE family
        if any(x in all_ids for x in ['suse', 'opensuse', 'sles']):
            return DistroFamily.SUSE

        # Arch family
        if any(x in all_ids for x in ['arch', 'manjaro']):
            return DistroFamily.ARCH

        # Alpine
        if 'alpine' in all_ids:
            return DistroFamily.ALPINE

        return DistroFamily.UNKNOWN

    def _detect_legacy(self) -> DistroInfo:
        """
        Detect distribution using legacy methods.

        Tries in order:
        1. /etc/lsb-release
        2. /etc/redhat-release
        3. /etc/debian_version
        4. uname

        Returns:
            DistroInfo object
        """
        # Try lsb-release
        exit_code, output, _ = self.ssh.execute_command(
            "cat /etc/lsb-release 2>/dev/null || cat /etc/*-release 2>/dev/null | head -1",
            check_exit_code=False
        )

        if exit_code == 0 and output:
            # Parse release info
            if 'Ubuntu' in output:
                version = re.search(r'(\d+\.\d+)', output)
                return DistroInfo(
                    family=DistroFamily.DEBIAN,
                    name="Ubuntu",
                    version=version.group(1) if version else "Unknown"
                )
            elif 'Debian' in output:
                version = re.search(r'(\d+)', output)
                return DistroInfo(
                    family=DistroFamily.DEBIAN,
                    name="Debian",
                    version=version.group(1) if version else "Unknown"
                )
            elif any(x in output for x in ['Red Hat', 'CentOS', 'Rocky']):
                version = re.search(r'(\d+)', output)
                return DistroInfo(
                    family=DistroFamily.REDHAT,
                    name=output.split()[0],
                    version=version.group(1) if version else "Unknown"
                )

        # Last resort: uname
        exit_code, output, _ = self.ssh.execute_command("uname -a", check_exit_code=False)

        return DistroInfo(
            family=DistroFamily.UNKNOWN,
            name="Linux",
            version="Unknown",
            raw_data={'uname': output}
        )

    def _detect_package_manager(self, distro_info: DistroInfo):
        """Detect package manager based on distribution family."""
        if distro_info.family == DistroFamily.DEBIAN:
            distro_info.package_manager = "apt"
        elif distro_info.family == DistroFamily.REDHAT:
            # Check if dnf or yum
            exit_code, _, _ = self.ssh.execute_command("which dnf", check_exit_code=False)
            distro_info.package_manager = "dnf" if exit_code == 0 else "yum"
        elif distro_info.family == DistroFamily.SUSE:
            distro_info.package_manager = "zypper"
        elif distro_info.family == DistroFamily.ARCH:
            distro_info.package_manager = "pacman"
        elif distro_info.family == DistroFamily.ALPINE:
            distro_info.package_manager = "apk"

    def _detect_mac_system(self, distro_info: DistroInfo):
        """Detect Mandatory Access Control system (SELinux, AppArmor)."""
        # Check SELinux
        exit_code, output, _ = self.ssh.execute_command(
            "getenforce 2>/dev/null",
            check_exit_code=False
        )
        if exit_code == 0 and output.strip():
            distro_info.mac_system = f"SELinux ({output.strip()})"
            return

        # Check AppArmor
        exit_code, output, _ = self.ssh.execute_command(
            "aa-status 2>/dev/null | head -1",
            check_exit_code=False
        )
        if exit_code == 0 and 'apparmor' in output.lower():
            distro_info.mac_system = "AppArmor"
            return

        distro_info.mac_system = "None"

    def _detect_firewall(self, distro_info: DistroInfo):
        """Detect firewall system."""
        # Check firewalld (RHEL/CentOS)
        exit_code, _, _ = self.ssh.execute_command(
            "systemctl is-active firewalld 2>/dev/null",
            check_exit_code=False
        )
        if exit_code == 0:
            distro_info.firewall = "firewalld"
            return

        # Check ufw (Ubuntu/Debian)
        exit_code, output, _ = self.ssh.execute_command(
            "ufw status 2>/dev/null",
            check_exit_code=False
        )
        if exit_code == 0 and 'Status:' in output:
            distro_info.firewall = "ufw"
            return

        # Check iptables
        exit_code, output, _ = self.ssh.execute_command(
            "iptables -L -n 2>/dev/null | wc -l",
            check_exit_code=False
        )
        if exit_code == 0 and output.strip() and int(output.strip()) > 0:
            distro_info.firewall = "iptables"
            return

        distro_info.firewall = "None"

    def _detect_init_system(self, distro_info: DistroInfo):
        """Detect init system (systemd vs sysvinit)."""
        exit_code, output, _ = self.ssh.execute_command(
            "ps -p 1 -o comm=",
            check_exit_code=False
        )
        if exit_code == 0:
            init = output.strip()
            distro_info.init_system = "systemd" if init == "systemd" else init


def detect_distribution(ssh_helper) -> DistroInfo:
    """
    Convenience function to detect Linux distribution.

    Args:
        ssh_helper: Connected SSHHelper instance

    Returns:
        DistroInfo object
    """
    detector = DistroDetector(ssh_helper)
    return detector.detect()

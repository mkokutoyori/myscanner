# Linux Security Vulnerabilities & Scanning Research

**Date:** 2025-11-10
**Purpose:** Research foundation for VulnScan platform plugin development
**Sources:** Web research, CIS Benchmarks, vendor documentation

---

## Table of Contents

1. [Common Linux Vulnerabilities by Category](#common-vulnerabilities)
2. [Distribution-Specific Issues](#distribution-specific)
3. [CIS Benchmarks Summary](#cis-benchmarks)
4. [Scanning Tools Analysis](#scanning-tools)
5. [Detection & Remediation Strategies](#detection-remediation)
6. [Recommended Scan Checks](#recommended-checks)

---

## 1. Common Linux Vulnerabilities by Category

### 1.1 SSH Misconfigurations (CRITICAL PRIORITY)

**Prevalence:** #1 attack vector for Linux systems in 2025
**Impact:** Remote access compromise, lateral movement

**Common Issues:**
- ✗ Root login enabled (`PermitRootLogin yes`)
- ✗ Password authentication instead of key-based
- ✗ Default port 22 exposed
- ✗ Weak/default credentials
- ✗ No rate limiting (brute-force vulnerable)
- ✗ No IP whitelisting/firewall rules
- ✗ Outdated SSH versions with known CVEs

**Detection Commands:**
```bash
grep -i '^PermitRootLogin' /etc/ssh/sshd_config
grep -i '^PasswordAuthentication' /etc/ssh/sshd_config
grep -i '^Port' /etc/ssh/sshd_config
ssh -V
```

**Remediation:**
- Set `PermitRootLogin no`
- Set `PasswordAuthentication no` (key-based auth only)
- Change default port (e.g., 2222)
- Implement Fail2Ban for brute-force protection
- Use IP whitelisting via firewall
- Update SSH to latest version

---

### 1.2 Firewall Issues (HIGH PRIORITY)

**Prevalence:** Very common, especially in development environments
**Impact:** Unnecessary exposure of services

**Common Issues:**
- ✗ Firewall disabled (iptables, ufw, firewalld inactive)
- ✗ All ports open (0.0.0.0/0 rules)
- ✗ Unnecessary services exposed externally
- ✗ Weak or default firewall rules
- ✗ IPv6 firewall not configured

**Detection Commands:**
```bash
# Check firewall status
systemctl is-active iptables firewalld ufw

# For ufw (Ubuntu/Debian)
ufw status verbose

# For firewalld (RHEL/CentOS)
firewall-cmd --state
firewall-cmd --list-all

# For iptables
iptables -L -n -v
```

**Remediation:**
- Enable firewall (ufw/firewalld/iptables)
- Default deny all, explicitly allow needed
- Close unnecessary ports
- Implement zone-based rules (public/internal)
- Configure IPv6 firewall

---

### 1.3 SELinux / AppArmor Disabled (HIGH PRIORITY)

**Prevalence:** Often disabled by admins due to complexity
**Impact:** Loss of Mandatory Access Control (MAC)

**Common Issues:**
- ✗ SELinux in permissive/disabled mode (RHEL/CentOS)
- ✗ AppArmor disabled/complain mode (Ubuntu/Debian)
- ✗ Policies not properly configured
- ✗ Contexts incorrectly set

**Detection Commands:**
```bash
# SELinux (RHEL/CentOS/Rocky)
getenforce
sestatus

# AppArmor (Ubuntu/Debian)
aa-status
apparmor_status
```

**Remediation:**
- Enable SELinux in enforcing mode
- Enable AppArmor profiles
- Audit logs for denials
- Proper context/profile configuration

---

### 1.4 Unpatched Software (CRITICAL PRIORITY)

**Prevalence:** #1 entry point for exploits
**Impact:** Known CVE exploitation

**Common Issues:**
- ✗ Outdated kernel with known vulnerabilities
- ✗ Unmaintained/EOL packages
- ✗ No automatic security updates
- ✗ Unpatched critical services (Apache, nginx, databases)
- ✗ Missing CVE patches

**Detection Commands:**
```bash
# Ubuntu/Debian
apt list --upgradable
apt-cache policy <package>
debsecan

# RHEL/CentOS/Rocky
yum updateinfo list security
dnf updateinfo --security
rpm -qa --last

# Check kernel
uname -r
```

**Remediation:**
- Enable automatic security updates
  - Ubuntu: `unattended-upgrades`
  - RHEL: `yum-cron` or `dnf-automatic`
- Regular patching schedule
- Subscribe to security mailing lists
- Use `needs-restarting` to identify services requiring restart

---

### 1.5 Weak File Permissions (MEDIUM PRIORITY)

**Prevalence:** Common in hastily configured systems
**Impact:** Privilege escalation, info disclosure

**Common Issues:**
- ✗ World-readable sensitive files (/etc/shadow, private keys)
- ✗ World-writable directories in PATH
- ✗ SUID/SGID binaries with vulnerabilities
- ✗ Weak permissions on cron jobs
- ✗ Logs readable by all users

**Detection Commands:**
```bash
# Find world-writable files
find / -type f -perm -002 2>/dev/null

# Find SUID/SGID binaries
find / -perm /6000 -type f 2>/dev/null

# Check critical files
ls -la /etc/shadow /etc/gshadow /root/.ssh/

# Check sudo config
ls -la /etc/sudoers /etc/sudoers.d/
```

**Remediation:**
- `/etc/shadow` should be 000 or 400
- Remove unnecessary SUID/SGID bits
- Secure cron jobs (600 permissions)
- Implement proper umask (022 or 027)

---

### 1.6 Open Ports & Unnecessary Services (MEDIUM PRIORITY)

**Prevalence:** Very common
**Impact:** Increased attack surface

**Common Issues:**
- ✗ Telnet (port 23) - unencrypted
- ✗ FTP (port 21) - unencrypted
- ✗ HTTP (port 80) without TLS
- ✗ VNC/RDP exposed to internet
- ✗ Database ports (3306, 5432, 1521) exposed
- ✗ Unnecessary daemons running

**Detection Commands:**
```bash
# Check listening ports
ss -tulpn
netstat -tulpn

# Check running services
systemctl list-units --type=service --state=running
```

**Remediation:**
- Disable telnet, use SSH
- Disable FTP, use SFTP/FTPS
- Enforce HTTPS only
- Bind services to localhost if not needed externally
- Remove unused packages

---

### 1.7 Weak Authentication & Password Policies (HIGH PRIORITY)

**Prevalence:** Common, especially in legacy systems
**Impact:** Account compromise

**Common Issues:**
- ✗ No password complexity requirements
- ✗ No password expiration
- ✗ Weak default passwords
- ✗ No account lockout policy
- ✗ Empty passwords allowed
- ✗ Shared accounts

**Detection Commands:**
```bash
# Check password policy
cat /etc/login.defs | grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE'

# Check PAM password requirements
cat /etc/pam.d/common-password  # Debian/Ubuntu
cat /etc/pam.d/password-auth    # RHEL/CentOS

# Find accounts without passwords
awk -F: '($2==""){print $1}' /etc/shadow

# Check for accounts with UID 0 (root-equivalent)
awk -F: '($3=="0"){print $1}' /etc/passwd
```

**Remediation:**
- Enforce strong passwords via PAM (pam_pwquality)
- Set password expiration (90 days recommended)
- Implement account lockout (pam_tally2/faillock)
- Remove/lock unused accounts
- No shared accounts

---

### 1.8 Logging & Auditing Disabled (MEDIUM PRIORITY)

**Prevalence:** Moderate
**Impact:** No forensic trail, compliance issues

**Common Issues:**
- ✗ auditd not running
- ✗ Logs not centralized (no syslog forwarding)
- ✗ Log rotation not configured (disk space issues)
- ✗ Insufficient logging of security events
- ✗ No log integrity checking

**Detection Commands:**
```bash
# Check auditd
systemctl status auditd

# Check rsyslog/syslog-ng
systemctl status rsyslog

# Check log rotation
ls -la /etc/logrotate.d/

# Check audit rules
auditctl -l
```

**Remediation:**
- Enable auditd with comprehensive rules
- Configure centralized logging
- Implement log rotation
- Use log integrity tools (AIDE, Tripwire)
- Enable process accounting (psacct)

---

### 1.9 Kernel & System Hardening (MEDIUM PRIORITY)

**Prevalence:** Rarely configured properly
**Impact:** Kernel exploits, privilege escalation

**Common Issues:**
- ✗ Kernel parameters not hardened (sysctl)
- ✗ Core dumps enabled (info disclosure)
- ✗ ASLR disabled
- ✗ No kernel exploit protection (LKRG not used)
- ✗ IPv4 forwarding enabled unnecessarily

**Detection Commands:**
```bash
# Check sysctl hardening
sysctl -a | grep -E 'kernel.dmesg_restrict|kernel.kptr_restrict'

# Check ASLR
cat /proc/sys/kernel/randomize_va_space

# Check core dumps
sysctl kernel.core_pattern
ulimit -c

# Check IP forwarding
sysctl net.ipv4.ip_forward
```

**Remediation:**
- Harden sysctl parameters
- Disable core dumps
- Enable ASLR (randomize_va_space=2)
- Install LKRG (Linux Kernel Runtime Guard)
- Disable IP forwarding unless router

---

### 1.10 Container & Virtualization Issues (2025 EMERGING THREAT)

**Prevalence:** Rapidly increasing
**Impact:** Container escapes, host compromise

**Common Issues:**
- ✗ Docker daemon exposed to network
- ✗ Containers running as root
- ✗ Privileged containers
- ✗ Host filesystem mounts
- ✗ Unpatched container images

**Detection Commands:**
```bash
# Check Docker socket exposure
ss -tulpn | grep docker

# Check running containers
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"

# Check container privilege
docker inspect <container> | grep -i privileged
```

**Remediation:**
- Secure Docker socket (TLS + firewall)
- Run containers as non-root
- Avoid privileged mode
- Scan container images (Trivy, Clair)
- Regular image updates

---

## 2. Distribution-Specific Issues

### 2.1 Ubuntu / Debian

**Package Manager:** APT
**Init System:** systemd
**MAC:** AppArmor (default)
**Firewall:** ufw (user-friendly iptables wrapper)

**Specific Vulnerabilities:**
- Snap packages with automatic updates (can break systems)
- AppArmor profiles often in complain mode
- `unattended-upgrades` may not be enabled by default
- Ubuntu Pro patches not applied (for older CVEs)

**Key Files to Check:**
- `/etc/apt/sources.list` - ensure security repos enabled
- `/etc/apparmor.d/` - check profile enforcement
- `/etc/apt/apt.conf.d/50unattended-upgrades` - auto-updates config
- `/var/log/apt/history.log` - package installation history

**Detection Commands:**
```bash
# Check security updates
apt list --upgradable | grep -i security

# Check AppArmor
aa-status | grep profiles

# Check unattended-upgrades
systemctl status unattended-upgrades
```

**Ubuntu 24.04 LTS (2025) Security Features:**
- FORTIFY_SOURCE=3 enabled by default
- Improved buffer overflow detection
- Enhanced AppArmor profiles

---

### 2.2 RHEL / CentOS / Rocky / AlmaLinux

**Package Manager:** DNF/YUM
**Init System:** systemd
**MAC:** SELinux (default)
**Firewall:** firewalld

**Specific Vulnerabilities:**
- SELinux often disabled by admins
- Subscription-Manager issues (RHEL only)
- Older CentOS 7 reaching EOL
- Weak default firewalld zones

**Key Files to Check:**
- `/etc/yum.repos.d/` - repository configuration
- `/etc/selinux/config` - SELinux mode
- `/etc/firewalld/zones/` - firewall zones
- `/var/log/audit/audit.log` - SELinux denials

**Detection Commands:**
```bash
# Check security updates
dnf updateinfo list security

# Check SELinux enforcing
getenforce

# Check subscriptions (RHEL)
subscription-manager status

# Check firewalld
firewall-cmd --get-active-zones
```

**RHEL 9 Security Features (2025):**
- CIS Benchmark 2.0.0 compliance
- Enhanced crypto policies
- Improved container security

---

### 2.3 SUSE / openSUSE

**Package Manager:** zypper
**Init System:** systemd
**MAC:** AppArmor
**Firewall:** firewalld / SuSEfirewall2

**Specific Vulnerabilities:**
- Less community tooling than Ubuntu/RHEL
- YaST misconfigurations
- Btrfs-specific issues (snapshots consuming space)

**Key Files:**
- `/etc/zypp/repos.d/` - repositories
- `/etc/sysconfig/` - system configuration

**Detection Commands:**
```bash
# Check updates
zypper list-updates --type security

# Check patches
zypper list-patches --severity=critical
```

---

## 3. CIS Benchmarks Summary

### 3.1 CIS Benchmark Levels

**Level 1 (Basic):**
- General environment security
- Essential for all systems
- Minimal performance impact
- Examples: Disable unused services, configure firewalls, enforce passwords

**Level 2 (Advanced):**
- High-security environments
- May impact performance/functionality
- Examples: Full disk encryption, extensive logging, kernel hardening

### 3.2 Major CIS Categories

1. **Initial Setup** - Filesystem configuration, partitioning
2. **Services** - Disable unnecessary services
3. **Network Configuration** - Firewall, IP forwarding, wireless
4. **Logging and Auditing** - auditd, rsyslog
5. **Access, Authentication and Authorization** - PAM, SSH, sudo
6. **System Maintenance** - User accounts, file permissions, updates

### 3.3 CIS Coverage by Distribution

| Distribution | Latest Benchmark | OpenSCAP Support | Notes |
|--------------|------------------|------------------|-------|
| Ubuntu 22.04 LTS | v2.0.0 | ✅ Yes | Official Ubuntu Security Guide available |
| Ubuntu 24.04 LTS | v1.0.0 (2025) | ✅ Yes | New release, limited tooling |
| RHEL 9 | v2.0.0 | ✅ Yes | Excellent OpenSCAP support |
| RHEL 8 | v3.0.0 | ✅ Yes | Mature tooling |
| Rocky Linux 9 | v2.0.0 | ✅ Yes | Based on RHEL benchmarks |
| Debian 11 | v1.0.0 | ⚠️ Limited | Community-maintained |
| openSUSE | v2.0.0 | ⚠️ Limited | Less common |

---

## 4. Scanning Tools Analysis

### 4.1 Lynis

**Type:** Host-based security auditor
**License:** GPL
**Best For:** Quick security assessments, system hardening guidance

**Strengths:**
- ✅ Runs on target system (no network scan needed)
- ✅ Opportunistic scanning (adapts to what's available)
- ✅ Minimal dependencies
- ✅ Works on latest OS versions
- ✅ Provides actionable recommendations
- ✅ Fast (typically 2-5 minutes)

**Weaknesses:**
- ❌ Not compliance-focused (no official CIS mappings)
- ❌ Doesn't enforce/fix issues (read-only)
- ❌ Output parsing can be tricky

**Usage:**
```bash
lynis audit system --quick
lynis show categories
```

**Key Checks:**
- Boot and services
- Kernel hardening
- Authentication (PAM, sudo)
- File integrity
- Cryptography
- Networking
- Time and synchronization

---

### 4.2 OpenSCAP

**Type:** SCAP-compliant security scanner
**License:** LGPL
**Best For:** Compliance testing, standardized reporting

**Strengths:**
- ✅ SCAP standard (portable compliance)
- ✅ Official CIS Benchmark profiles
- ✅ Remediation scripts (can auto-fix)
- ✅ Enterprise-grade reporting
- ✅ Integration with orchestration tools

**Weaknesses:**
- ❌ Complex XML content (steep learning curve)
- ❌ Less portable across distributions
- ❌ Slower than Lynis
- ❌ More dependencies

**Usage:**
```bash
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

oscap xccdf generate report results.xml > report.html
```

**Key Profiles:**
- CIS Level 1/2
- STIG (DoD)
- PCI-DSS
- HIPAA

---

### 4.3 Comparison Matrix

| Feature | Lynis | OpenSCAP | Custom Script |
|---------|-------|----------|---------------|
| Speed | ⭐⭐⭐ Fast | ⭐⭐ Moderate | ⭐⭐⭐ Fast |
| Compliance | ⭐⭐ Informal | ⭐⭐⭐ Official | ⭐ None |
| Ease of Use | ⭐⭐⭐ Easy | ⭐ Complex | ⭐⭐ Medium |
| Portability | ⭐⭐⭐ Excellent | ⭐⭐ Good | ⭐⭐⭐ Excellent |
| Remediation | ❌ No | ✅ Yes | ✅ Possible |
| Reporting | ⭐⭐ Basic | ⭐⭐⭐ Enterprise | ⭐ DIY |

---

## 5. Detection & Remediation Strategies

### 5.1 Detection Strategy (3-Tier Approach)

**Tier 1: Critical Checks (Run Always)**
- SSH configuration
- Firewall status
- SELinux/AppArmor status
- Unpatched kernel/critical packages
- Root account security

**Tier 2: Important Checks (Run on Full Scan)**
- All package updates
- File permissions
- Running services audit
- Password policies
- Logging configuration

**Tier 3: Compliance Checks (Run on Demand)**
- Full CIS benchmark via OpenSCAP
- Custom organizational policies
- Detailed file integrity
- Historical log analysis

### 5.2 Remediation Priority Matrix

| Severity | Finding Example | SLA | Auto-Fix? |
|----------|----------------|-----|-----------|
| CRITICAL | Root SSH enabled | 24h | ✅ Yes (with approval) |
| CRITICAL | Unpatched kernel CVE | 48h | ✅ Yes (with reboot) |
| HIGH | Firewall disabled | 48h | ✅ Yes |
| HIGH | SELinux disabled | 1 week | ⚠️ Careful (may break apps) |
| MEDIUM | Weak password policy | 2 weeks | ✅ Yes |
| MEDIUM | Unnecessary services | 1 month | ✅ Yes |
| LOW | Missing log rotation | 3 months | ✅ Yes |
| INFO | Old kernel available | N/A | ❌ No (user decides) |

---

## 6. Recommended Scan Checks

### 6.1 Comprehensive Check List (by Priority)

#### P0 - CRITICAL SECURITY CHECKS

```yaml
ssh_security:
  - name: "SSH Root Login"
    check: "grep '^PermitRootLogin' /etc/ssh/sshd_config"
    expect: "no"
    severity: CRITICAL
    cve: []
    cwe: ["CWE-284"]

  - name: "SSH Password Authentication"
    check: "grep '^PasswordAuthentication' /etc/ssh/sshd_config"
    expect: "no"
    severity: HIGH
    remediation: "Set PasswordAuthentication no and use key-based auth"

firewall_security:
  - name: "Firewall Active"
    check: "systemctl is-active firewalld || systemctl is-active ufw || systemctl is-active iptables"
    expect: "active"
    severity: CRITICAL

  - name: "Default Deny Policy"
    check: "iptables -L -n | grep -i 'chain input.*drop'"
    expect: "match"
    severity: HIGH

mac_security:
  - name: "SELinux Enforcing"
    distro: ["rhel", "centos", "rocky", "alma", "fedora"]
    check: "getenforce"
    expect: "Enforcing"
    severity: HIGH

  - name: "AppArmor Enabled"
    distro: ["ubuntu", "debian", "suse"]
    check: "aa-status | grep 'apparmor module is loaded'"
    expect: "match"
    severity: HIGH

package_security:
  - name: "Security Updates Available"
    check_ubuntu: "apt list --upgradable 2>/dev/null | grep -i security"
    check_rhel: "dnf updateinfo list security --available"
    severity: CRITICAL

  - name: "Unpatched Kernel"
    check: "needs-restarting -r"
    severity: CRITICAL
```

#### P1 - HIGH PRIORITY CHECKS

```yaml
authentication:
  - name: "Empty Passwords"
    check: "awk -F: '($2==\"\"){print $1}' /etc/shadow"
    expect: "empty"
    severity: HIGH

  - name: "Duplicate UID 0"
    check: "awk -F: '($3==\"0\" && $1!=\"root\"){print $1}' /etc/passwd"
    expect: "empty"
    severity: CRITICAL

  - name: "Password Policy"
    check: "grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS' /etc/login.defs"
    expect: "PASS_MAX_DAYS <= 90"
    severity: MEDIUM

services:
  - name: "Telnet Service"
    check: "ss -tulpn | grep ':23'"
    expect: "not_found"
    severity: CRITICAL

  - name: "FTP Service"
    check: "ss -tulpn | grep ':21'"
    expect: "not_found"
    severity: HIGH

  - name: "Unnecessary Services"
    check: "systemctl list-units --type=service --state=running"
    analyze: ["bluetooth", "cups", "avahi", "rpcbind"]
    severity: MEDIUM
```

#### P2 - MEDIUM PRIORITY CHECKS

```yaml
file_permissions:
  - name: "World Writable Files"
    check: "find / -xdev -type f -perm -0002 2>/dev/null | head -20"
    expect: "minimal"
    severity: MEDIUM

  - name: "SUID Binaries"
    check: "find / -xdev -perm /6000 -type f 2>/dev/null"
    analyze: "compare_with_baseline"
    severity: MEDIUM

  - name: "Shadow File Permissions"
    check: "stat -c '%a' /etc/shadow"
    expect: "000|400"
    severity: HIGH

logging:
  - name: "Auditd Running"
    check: "systemctl is-active auditd"
    expect: "active"
    severity: MEDIUM

  - name: "Rsyslog Running"
    check: "systemctl is-active rsyslog"
    expect: "active"
    severity: MEDIUM

  - name: "Log Rotation Configured"
    check: "ls /etc/logrotate.d/"
    expect: "files_present"
    severity: LOW
```

#### P3 - LOW PRIORITY / HARDENING CHECKS

```yaml
kernel_hardening:
  - name: "ASLR Enabled"
    check: "sysctl kernel.randomize_va_space"
    expect: "2"
    severity: MEDIUM

  - name: "Core Dumps Disabled"
    check: "sysctl kernel.core_pattern; ulimit -c"
    expect: "disabled"
    severity: LOW

  - name: "IP Forwarding Disabled"
    check: "sysctl net.ipv4.ip_forward"
    expect: "0"
    severity: MEDIUM
    condition: "unless_router"

system_hardening:
  - name: "Automatic Updates"
    check_ubuntu: "systemctl is-enabled unattended-upgrades"
    check_rhel: "systemctl is-enabled dnf-automatic.timer"
    expect: "enabled"
    severity: MEDIUM

  - name: "Fail2Ban Installed"
    check: "systemctl is-active fail2ban"
    expect: "active"
    severity: MEDIUM
    recommended: true
```

---

## 7. Implementation Recommendations

### 7.1 Plugin Architecture

**Proposed Structure:**
```
backend/plugins/
├── linux/
│   ├── ubuntu_plugin.py          # Ubuntu-specific checks
│   ├── rhel_plugin.py             # RHEL/CentOS/Rocky
│   ├── debian_plugin.py           # Debian-specific
│   ├── suse_plugin.py             # SUSE/openSUSE
│   └── generic_linux_plugin.py    # Distribution-agnostic
├── scanners/
│   ├── lynis_scanner.py           # Lynis wrapper
│   ├── openscap_scanner.py        # OpenSCAP wrapper
│   └── custom_scanner.py          # Custom security checks
└── detectors/
    └── distro_detector.py         # Auto-detect distribution
```

### 7.2 Distribution Detection Logic

```python
def detect_linux_distribution():
    """
    Detects Linux distribution and returns normalized info.

    Returns:
        {
            'id': 'ubuntu',  # Normalized ID
            'version': '22.04',
            'version_codename': 'jammy',
            'family': 'debian',  # debian, rhel, suse, arch
            'like': ['debian']
        }
    """
    # Priority 1: /etc/os-release (modern standard)
    if os.path.exists('/etc/os-release'):
        return parse_os_release()

    # Priority 2: lsb_release command
    elif command_exists('lsb_release'):
        return parse_lsb_release()

    # Priority 3: Legacy distribution-specific files
    elif os.path.exists('/etc/redhat-release'):
        return parse_redhat_release()
    elif os.path.exists('/etc/debian_version'):
        return {'id': 'debian', 'family': 'debian'}

    # Fallback: Unknown
    return {'id': 'unknown', 'family': 'unknown'}
```

### 7.3 Scan Orchestration Flow

```
1. Connect to target system (SSH)
2. Detect distribution → distro_detector.detect()
3. Select appropriate plugin → plugin_selector.get_plugin(distro)
4. Run tiered scans:
   a. Tier 1: Critical checks (always)
   b. Tier 2: Full audit (if requested)
   c. Tier 3: Compliance (if requested)
5. Run scanner tools:
   a. Lynis (if available)
   b. OpenSCAP (if available and CIS profile requested)
6. Normalize findings → standard PluginFinding format
7. Store in database
8. Return results
```

---

## 8. References

**CIS Benchmarks:**
- https://www.cisecurity.org/cis-benchmarks
- CIS Rocky Linux Benchmark
- CIS Red Hat Enterprise Linux Benchmark
- CIS Ubuntu Linux Benchmark

**Security Guides:**
- RHEL 9 Security Hardening Guide (Red Hat official)
- Ubuntu Security Guide (Ubuntu official)
- Linux Security Expert (linuxsecurity.expert)
- nixCraft Linux Security Tips

**Tools:**
- Lynis: https://cisofy.com/lynis
- OpenSCAP: https://www.open-scap.org
- Linux Audit: https://linux-audit.com

**CVE/Vulnerability Databases:**
- NVD: https://nvd.nist.gov
- Ubuntu CVE Tracker: https://ubuntu.com/security/cves
- Red Hat CVE Database: https://access.redhat.com/security/security-updates/cve

---

**Document Version:** 1.0
**Last Updated:** 2025-11-10
**Next Review:** Before Sprint 3 implementation


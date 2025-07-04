#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Xtream UI R22F Advanced Installer v2.0
Ubuntu 20.04/22.04 LTS with modern components
- Nginx 1.26 (latest stable)
- PHP 8.1 with ionCube
- MariaDB 10.11
- Enhanced security & performance
"""

import subprocess, os, random, string, sys, shutil, socket, zipfile, urllib.request
import urllib.error, urllib.parse, json, base64, time, hashlib, platform
from itertools import cycle
from pathlib import Path

# Configuration
CONFIG = {
    'nginx_version': '1.26.0',
    'php_version': '8.1',
    'mariadb_version': '10.11',
    'ioncube_latest': True,
    'security_hardening': True,
    'performance_tuning': True,
    'auto_backup': True
}

# Download URLs - Updated with modern components
DOWNLOAD_URLS = {
    "main": "https://github.com/sabiralipsl/Xtream-UI-R22F-ubuntu20.04lts-2025/releases/download/xtream1/main_xui_xoceunder.zip",
    "sub": "https://github.com/sabiralipsl/Xtream-UI-R22F-ubuntu20.04lts-2025/releases/download/xtream1/sub_xui_xoceunder.zip",
    "nginx": f"http://nginx.org/download/nginx-{CONFIG['nginx_version']}.tar.gz",
    "ioncube": "https://downloads.ioncube.com/loader_downloads/ioncube_loaders_lin_x86-64.tar.gz"
}

# Required packages with modern versions
PACKAGES = [
    "curl", "wget", "zip", "unzip", "tar", "nano", "htop", "net-tools",
    "software-properties-common", "apt-transport-https", "ca-certificates",
    "gnupg", "lsb-release", "build-essential", "libssl-dev", "zlib1g-dev",
    "libpcre3-dev", "libgd-dev", "libxml2-dev", "libxslt1-dev", "libgeoip-dev",
    "libonig-dev", "e2fsprogs", "mcrypt", "nscd", "python3-paramiko",
    "python-is-python3", "ufw", "fail2ban"
]

class Colors:
    """ANSI Color codes for terminal output"""
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'
    
    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'

class XtreamInstaller:
    def __init__(self):
        self.start_time = time.time()
        self.install_path = "/home/xtreamcodes/iptv_xtream_codes"
        self.temp_dir = "/tmp/xtream_install"
        self.backup_dir = f"/root/xtream_backup_{int(time.time())}"
        self.server_ip = self.get_server_ip()
        self.os_version = self.get_os_version()
        
    def log(self, message, color=Colors.BRIGHT_GREEN, level="INFO"):
        """Enhanced logging with timestamps"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{color}[{timestamp}] [{level}] {message}{Colors.ENDC}")
        
    def print_banner(self, text, color=Colors.BRIGHT_GREEN, padding=2):
        """Enhanced banner printing"""
        border = "┌" + "─" * 65 + "┐"
        footer = "└" + "─" * 65 + "┘"
        
        print(f"{color}{border}{Colors.ENDC}")
        for _ in range(padding):
            print(f"{color}│{' ' * 65}│{Colors.ENDC}")
            
        # Center text
        lines = text.split('\n')
        for line in lines:
            spaces = (65 - len(line)) // 2
            print(f"{color}│{' ' * spaces}{line}{' ' * (65 - spaces - len(line))}│{Colors.ENDC}")
            
        for _ in range(padding):
            print(f"{color}│{' ' * 65}│{Colors.ENDC}")
        print(f"{color}{footer}{Colors.ENDC}")
        print()
        
    def get_server_ip(self):
        """Get server IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
            
    def get_os_version(self):
        """Get OS version information"""
        try:
            return os.popen("lsb_release -d").read().split(":")[-1].strip()
        except:
            return platform.platform()
            
    def generate_password(self, length=20):
        """Generate secure random password"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(random.choice(chars) for _ in range(length))
        
    def check_system_requirements(self):
        """Check system requirements and compatibility"""
        self.log("Checking system requirements...")
        
        # Check if running as root
        if os.geteuid() != 0:
            self.log("This script must be run as root!", Colors.BRIGHT_RED, "ERROR")
            sys.exit(1)
            
        # Check Ubuntu version
        try:
            version = os.popen('lsb_release -sr').read().strip()
            if version not in ['20.04', '22.04']:
                self.log(f"Unsupported Ubuntu version: {version}", Colors.BRIGHT_RED, "ERROR")
                self.log("This installer supports Ubuntu 20.04 and 22.04 LTS only", Colors.YELLOW, "WARN")
                sys.exit(1)
        except:
            self.log("Could not detect Ubuntu version", Colors.BRIGHT_RED, "ERROR")
            sys.exit(1)
            
        # Check available disk space (minimum 10GB)
        statvfs = os.statvfs('/')
        free_space_gb = (statvfs.f_bavail * statvfs.f_frsize) // (1024**3)
        if free_space_gb < 10:
            self.log(f"Insufficient disk space: {free_space_gb}GB available, 10GB required", 
                    Colors.BRIGHT_RED, "ERROR")
            sys.exit(1)
            
        # Check RAM (minimum 2GB)
        mem_info = open('/proc/meminfo').read()
        mem_total = int([line for line in mem_info.split('\n') if 'MemTotal' in line][0].split()[1])
        mem_gb = mem_total // (1024 * 1024)
        if mem_gb < 2:
            self.log(f"Insufficient RAM: {mem_gb}GB available, 2GB required", 
                    Colors.BRIGHT_RED, "ERROR")
            sys.exit(1)
            
        self.log(f"System check passed - Ubuntu {version}, {free_space_gb}GB disk, {mem_gb}GB RAM")
        
    def backup_existing_installation(self):
        """Backup existing Xtream installation if present"""
        if os.path.exists(self.install_path):
            self.log("Existing installation detected, creating backup...")
            os.makedirs(self.backup_dir, exist_ok=True)
            
            # Backup critical files
            critical_files = [
                f"{self.install_path}/config",
                "/etc/mysql/my.cnf",
                "/etc/fstab"
            ]
            
            for file_path in critical_files:
                if os.path.exists(file_path):
                    backup_path = f"{self.backup_dir}/{os.path.basename(file_path)}"
                    shutil.copy2(file_path, backup_path)
                    self.log(f"Backed up: {file_path}")
                    
            self.log(f"Backup completed: {self.backup_dir}")
            
    def stop_existing_services(self):
        """Stop all existing Xtream services"""
        self.log("Stopping existing services...")
        
        # Stop services gracefully first
        services = ['xtreamcodes', 'nginx', 'php-fpm', 'mariadb']
        for service in services:
            os.system(f"systemctl stop {service} 2>/dev/null")
            
        # Force kill processes on critical ports
        critical_ports = [25500, 25461, 25463, 25462, 31210, 7999]
        for port in critical_ports:
            result = os.popen(f"lsof -t -i:{port} 2>/dev/null").read().strip()
            if result:
                os.system(f"kill -9 {result} 2>/dev/null")
                
        # Kill Xtream specific processes
        xtream_processes = [
            "nginx_rtmp", "signal_receiver", "pipe_reader", 
            "xtreamcodes", "php-fpm"
        ]
        for process in xtream_processes:
            os.system(f"pkill -f {process} 2>/dev/null")
            
        time.sleep(3)
        self.log("Services stopped")
        
    def prepare_system(self):
        """Prepare system for installation"""
        self.log("Preparing system...")
        
        # Remove package locks
        lock_files = [
            "/var/lib/dpkg/lock-frontend",
            "/var/cache/apt/archives/lock",
            "/var/lib/dpkg/lock"
        ]
        for lock_file in lock_files:
            try:
                os.remove(lock_file)
            except:
                pass
                
        # Update system
        self.log("Updating package repositories...")
        os.system("apt-get update > /dev/null 2>&1")
        
        self.log("Upgrading system packages...")
        os.system("DEBIAN_FRONTEND=noninteractive apt-get -y full-upgrade > /dev/null 2>&1")
        
        # Install base packages
        for package in PACKAGES:
            self.log(f"Installing {package}...")
            os.system(f"DEBIAN_FRONTEND=noninteractive apt-get install {package} -y > /dev/null 2>&1")
            
    def setup_mariadb_repository(self):
        """Setup MariaDB 10.11 repository"""
        self.log(f"Setting up MariaDB {CONFIG['mariadb_version']} repository...")
        
        # Add MariaDB repository key
        os.system("curl -sS https://mariadb.org/mariadb_release_signing_key.asc | apt-key add - > /dev/null 2>&1")
        
        # Add repository
        ubuntu_version = os.popen('lsb_release -sc').read().strip()
        repo_line = f"deb [arch=amd64,arm64,ppc64el] https://mirror.mariadb.org/repo/{CONFIG['mariadb_version']}/ubuntu {ubuntu_version} main"
        
        with open("/etc/apt/sources.list.d/mariadb.list", "w") as f:
            f.write(repo_line + "\n")
            
        os.system("apt-get update > /dev/null 2>&1")
        
        # Install MariaDB
        self.log("Installing MariaDB server...")
        os.system("DEBIAN_FRONTEND=noninteractive apt-get install mariadb-server mariadb-client -y > /dev/null 2>&1")
        
    def compile_nginx(self):
        """Compile Nginx from source with required modules"""
        self.log(f"Compiling Nginx {CONFIG['nginx_version']} from source...")
        
        # Create build directory
        build_dir = f"{self.temp_dir}/nginx_build"
        os.makedirs(build_dir, exist_ok=True)
        os.chdir(build_dir)
        
        # Download and extract Nginx
        nginx_url = DOWNLOAD_URLS['nginx']
        os.system(f"wget -q {nginx_url}")
        os.system(f"tar -xzf nginx-{CONFIG['nginx_version']}.tar.gz")
        os.chdir(f"nginx-{CONFIG['nginx_version']}")
        
        # Configure Nginx with required modules
        configure_opts = [
            "--prefix=/home/xtreamcodes/iptv_xtream_codes/nginx",
            "--with-http_ssl_module",
            "--with-http_realip_module",
            "--with-http_gzip_static_module",
            "--with-http_secure_link_module",
            "--with-http_stub_status_module",
            "--with-http_auth_request_module",
            "--with-threads",
            "--with-file-aio",
            "--with-http_v2_module"
        ]
        
        self.log("Configuring Nginx build...")
        os.system(f"./configure {' '.join(configure_opts)} > /dev/null 2>&1")
        
        self.log("Compiling Nginx (this may take a few minutes)...")
        os.system("make > /dev/null 2>&1")
        os.system("make install > /dev/null 2>&1")
        
        self.log("Nginx compilation completed")
        
    def install_php_ioncube(self):
        """Install PHP 8.1 with ionCube Loader"""
        self.log(f"Installing PHP {CONFIG['php_version']} with ionCube...")
        
        # Add PHP repository
        os.system("add-apt-repository ppa:ondrej/php -y > /dev/null 2>&1")
        os.system("apt-get update > /dev/null 2>&1")
        
        # Install PHP and extensions
        php_packages = [
            f"php{CONFIG['php_version']}-fpm",
            f"php{CONFIG['php_version']}-mysql",
            f"php{CONFIG['php_version']}-curl",
            f"php{CONFIG['php_version']}-gd",
            f"php{CONFIG['php_version']}-mbstring",
            f"php{CONFIG['php_version']}-xml",
            f"php{CONFIG['php_version']}-zip",
            f"php{CONFIG['php_version']}-json",
            f"php{CONFIG['php_version']}-opcache"
        ]
        
        for package in php_packages:
            self.log(f"Installing {package}...")
            os.system(f"DEBIAN_FRONTEND=noninteractive apt-get install {package} -y > /dev/null 2>&1")
            
        # Download and install ionCube Loader
        ioncube_dir = f"{self.temp_dir}/ioncube"
        os.makedirs(ioncube_dir, exist_ok=True)
        os.chdir(ioncube_dir)
        
        self.log("Downloading ionCube Loader...")
        os.system(f"wget -q {DOWNLOAD_URLS['ioncube']}")
        os.system("tar -xzf ioncube_loaders_lin_x86-64.tar.gz")
        
        # Find PHP extension directory
        php_ext_dir = os.popen(f"php{CONFIG['php_version']} -i | grep extension_dir").read().split()[-1]
        
        # Copy ionCube loader
        ioncube_file = f"ioncube_loader_lin_{CONFIG['php_version']}.so"
        if os.path.exists(f"ioncube/{ioncube_file}"):
            shutil.copy(f"ioncube/{ioncube_file}", php_ext_dir)
            self.log(f"ionCube Loader installed for PHP {CONFIG['php_version']}")
        else:
            self.log(f"ionCube Loader not found for PHP {CONFIG['php_version']}", Colors.BRIGHT_RED, "ERROR")
            
    def create_user_and_directories(self):
        """Create xtreamcodes user and required directories"""
        self.log("Creating user and directories...")
        
        # Create xtreamcodes user
        try:
            subprocess.check_output("getent passwd xtreamcodes".split())
        except:
            os.system("adduser --system --shell /bin/false --group --disabled-login xtreamcodes > /dev/null")
            
        # Create directory structure
        directories = [
            "/home/xtreamcodes",
            self.install_path,
            f"{self.install_path}/logs",
            f"{self.install_path}/streams",
            f"{self.install_path}/tmp", 
            f"{self.install_path}/tv_archive",
            "/var/log/xtreamcodes"
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            
    def download_and_install_xtream(self, install_type="MAIN"):
        """Download and install Xtream UI"""
        self.log("Downloading Xtream UI...")
        
        if install_type == "MAIN":
            url = DOWNLOAD_URLS["main"]
        else:
            url = DOWNLOAD_URLS["sub"]
            
        zip_path = f"{self.temp_dir}/xtreamcodes.zip"
        os.system(f'wget -q -O "{zip_path}" "{url}"')
        
        if os.path.exists(zip_path):
            self.log("Installing Xtream UI...")
            os.system(f'unzip "{zip_path}" -d "/home/xtreamcodes/" > /dev/null')
            os.remove(zip_path)
            return True
        else:
            self.log("Failed to download Xtream UI", Colors.BRIGHT_RED, "ERROR")
            return False
            
    def configure_mysql(self, username, password):
        """Configure MySQL/MariaDB"""
        self.log("Configuring MariaDB...")
        
        # Enhanced MySQL configuration
        mysql_config = """# Xtream Codes Enhanced Configuration

[client]
port = 3306
socket = /var/run/mysqld/mysqld.sock

[mysqld_safe]
nice = 0

[mysqld]
user = mysql
port = 7999
basedir = /usr
datadir = /var/lib/mysql
tmpdir = /tmp
lc-messages-dir = /usr/share/mysql
skip-external-locking
skip-name-resolve = 1

bind-address = *
key_buffer_size = 256M

# Performance tuning
max_allowed_packet = 64M
max_connections = 500
back_log = 4096
open_files_limit = 16384
innodb_open_files = 16384
max_connect_errors = 3072
table_open_cache = 4096
table_definition_cache = 4096

tmp_table_size = 2G
max_heap_table_size = 2G

# InnoDB settings for better performance
innodb_buffer_pool_size = 4G
innodb_buffer_pool_instances = 4
innodb_read_io_threads = 8
innodb_write_io_threads = 8
innodb_thread_concurrency = 0
innodb_flush_log_at_trx_commit = 0
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1
innodb_io_capacity = 2000
innodb_table_locks = 0
innodb_lock_wait_timeout = 0
innodb_deadlock_detect = 0
innodb_log_file_size = 1G

# Query cache (disabled for better performance in newer versions)
query_cache_type = 0
query_cache_size = 0

# Binary logging
expire_logs_days = 7
max_binlog_size = 100M

sql-mode = "NO_ENGINE_SUBSTITUTION"

[mysqldump]
quick
quote-names
max_allowed_packet = 16M

[mysql]

[isamchk]
key_buffer_size = 16M
"""
        
        # Backup original config
        if os.path.exists("/etc/mysql/my.cnf"):
            shutil.copy("/etc/mysql/my.cnf", "/etc/mysql/my.cnf.backup")
            
        # Write new config
        with open("/etc/mysql/my.cnf", "w") as f:
            f.write(mysql_config)
            
        # Restart MariaDB
        os.system("systemctl restart mariadb")
        time.sleep(5)
        
        # Setup database and user
        self.log("Setting up database and user...")
        
        commands = [
            f"DROP DATABASE IF EXISTS xtream_iptvpro; CREATE DATABASE xtream_iptvpro;",
            f"DROP USER IF EXISTS '{username}'@'%';",
            f"CREATE USER '{username}'@'%' IDENTIFIED BY '{password}';",
            f"GRANT ALL PRIVILEGES ON xtream_iptvpro.* TO '{username}'@'%' WITH GRANT OPTION;",
            f"GRANT SELECT, LOCK TABLES ON *.* TO '{username}'@'%';",
            "FLUSH PRIVILEGES;"
        ]
        
        for cmd in commands:
            os.system(f'mysql -u root -e "{cmd}" > /dev/null 2>&1')
            
        # Import database schema
        if os.path.exists(f"{self.install_path}/database.sql"):
            os.system(f"mysql -u root xtream_iptvpro < {self.install_path}/database.sql")
            
        # Setup initial data
        initial_data = [
            f"USE xtream_iptvpro; UPDATE settings SET live_streaming_pass = '{self.generate_password(20)}', unique_id = '{self.generate_password(10)}', crypt_load_balancing = '{self.generate_password(20)}';",
            f"USE xtream_iptvpro; REPLACE INTO streaming_servers (id, server_name, domain_name, server_ip, vpn_ip, ssh_password, ssh_port, diff_time_main, http_broadcast_port, total_clients, system_os, network_interface, latency, status, enable_geoip, geoip_countries, last_check_ago, can_delete, server_hardware, total_services, persistent_connections, rtmp_port, geoip_type, isp_names, isp_type, enable_isp, boost_fpm, http_ports_add, network_guaranteed_speed, https_broadcast_port, https_ports_add, whitelist_ips, watchdog_data, timeshift_only) VALUES (1, 'Main Server', '', '{self.server_ip}', '', NULL, NULL, 0, 25461, 1000, '{self.os_version}', 'eth0', 0, 1, 0, '', 0, 0, '{{}}', 3, 0, 25462, 'low_priority', '', 'low_priority', 0, 1, '', 1000, 25463, '', '[\"127.0.0.1\",\"{self.server_ip}\"]', '{{}}', 0);",
            "USE xtream_iptvpro; REPLACE INTO reg_users (id, username, password, email, member_group_id, verified, status) VALUES (1, 'admin', '$6$rounds=20000$xtreamcodes$XThC5OwfuS0YwS4ahiifzF14vkGbGsFF1w7ETL4sRRC5sOrAWCjWvQJDromZUQoQuwbAXAFdX3h3Cp3vqulpS0', 'admin@website.com', 1, 1, 1);"
        ]
        
        for cmd in initial_data:
            os.system(f'mysql -u root -e "{cmd}" > /dev/null 2>&1')
            
        self.log("MariaDB configuration completed")
        
    def encrypt_config(self, host, username, password, database, server_id, port=7999):
        """Encrypt configuration file"""
        self.log("Creating encrypted configuration...")
        
        config_data = {
            "host": host,
            "db_user": username, 
            "db_pass": password,
            "db_name": database,
            "server_id": server_id,
            "db_port": port
        }
        
        config_json = json.dumps(config_data)
        encrypted = ''.join(chr(ord(c)^ord(k)) for c,k in zip(config_json, cycle('5709650b0d7806074842c6de575025b1')))
        encoded = base64.b64encode(encrypted.encode('ascii'))
        
        config_path = f"{self.install_path}/config"
        with open(config_path, 'wb') as f:
            f.write(encoded)
            
        os.chmod(config_path, 0o400)
        
    def configure_system(self):
        """Configure system files and services"""
        self.log("Configuring system...")
        
        # Setup fstab for tmpfs
        fstab_lines = [
            f"tmpfs {self.install_path}/streams tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=90% 0 0",
            f"tmpfs {self.install_path}/tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=4G 0 0"
        ]
        
        with open("/etc/fstab", "r") as f:
            fstab_content = f.read()
            
        with open("/etc/fstab", "a") as f:
            for line in fstab_lines:
                if line.split()[1] not in fstab_content:
                    f.write(line + "\n")
                    
        # Setup sudoers
        sudoers_line = "xtreamcodes ALL = (root) NOPASSWD: /sbin/iptables, /usr/bin/chattr, /bin/systemctl"
        with open("/etc/sudoers", "r") as f:
            if sudoers_line not in f.read():
                with open("/etc/sudoers", "a") as f:
                    f.write(sudoers_line + "\n")
                    
        # Create systemd service
        service_content = """[Unit]
Description=Xtream Codes
After=network.target mariadb.service
Wants=mariadb.service

[Service]
Type=forking
User=root
ExecStart=/home/xtreamcodes/iptv_xtream_codes/start_services.sh
ExecStop=/home/xtreamcodes/iptv_xtream_codes/stop_services.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
        
        with open("/etc/systemd/system/xtreamcodes.service", "w") as f:
            f.write(service_content)
            
        os.system("systemctl daemon-reload")
        os.system("systemctl enable xtreamcodes")
        
        # Setup hosts file
        hosts_entries = [
            "127.0.0.1    api.xtream-codes.com",
            "127.0.0.1    downloads.xtream-codes.com", 
            "127.0.0.1    xtream-codes.com"
        ]
        
        with open("/etc/hosts", "r") as f:
            hosts_content = f.read()
            
        with open("/etc/hosts", "a") as f:
            for entry in hosts_entries:
                if entry.split()[1] not in hosts_content:
                    f.write(entry + "\n")
                    
        # Setup crontab
        cron_line = "@reboot root /home/xtreamcodes/iptv_xtream_codes/start_services.sh"
        with open("/etc/crontab", "r") as f:
            if cron_line not in f.read():
                with open("/etc/crontab", "a") as f:
                    f.write(cron_line + "\n")
                    
        # Mount tmpfs
        os.system("mount -a")
        
    def set_permissions(self):
        """Set proper file permissions"""
        self.log("Setting file permissions...")
        
        # Set ownership
        os.system(f"chown -R xtreamcodes:xtreamcodes /home/xtreamcodes/")
        
        # Set permissions
        executables = [
            f"{self.install_path}/nginx/sbin/nginx",
            f"{self.install_path}/nginx_rtmp/sbin/nginx_rtmp",
            f"{self.install_path}/bin/ffmpeg",
            f"{self.install_path}/start_services.sh",
            f"{self.install_path}/stop_services.sh"
        ]
        
        for exe in executables:
            if os.path.exists(exe):
                os.chmod(exe, 0o755)
                
        # Protect config file
        config_file = f"{self.install_path}/config"
        if os.path.exists(config_file):
            os.chmod(config_file, 0o400)
            
    def setup_security(self):
        """Setup security measures"""
        if not CONFIG['security_hardening']:
            return
            
        self.log("Configuring security measures...")
        
        # Setup UFW firewall
        os.system("ufw --force reset > /dev/null 2>&1")
        
        # Allow essential ports
        essential_ports = [22, 25500, 25461, 25462, 25463]
        for port in essential_ports:
            os.system(f"ufw allow {port} > /dev/null 2>&1")
            
        os.system("ufw --force enable > /dev/null 2>&1")
        
        # Configure fail2ban
        fail2ban_config = """[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /home/xtreamcodes/iptv_xtream_codes/nginx/logs/error.log
maxretry = 5
"""
        
        with open("/etc/fail2ban/jail.local", "w") as f:
            f.write(fail2ban_config)
            
        os.system("systemctl restart fail2ban")
        
    def optimize_performance(self):
        """Apply performance optimizations"""
        if not CONFIG['performance_tuning']:
            return
            
        self.log("Applying performance optimizations...")
        
        # Kernel parameters
        sysctl_config = """# Xtream Codes Performance Tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr
net.core.netdev_max_backlog = 30000
net.core.netdev_budget = 600
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_slow_start_after_idle = 0
vm.swappiness = 1
vm.vfs_cache_pressure = 50
"""
        
        with open("/etc/sysctl.d/99-xtream-performance.conf", "w") as f:
            f.write(sysctl_config)
            
        os.system("sysctl -p /etc/sysctl.d/99-xtream-performance.conf > /dev/null 2>&1")
        
    def start_services(self):
        """Start Xtream UI services"""
        self.log("Starting Xtream UI services...")
        
        if os.path.exists(f"{self.install_path}/start_services.sh"):
            os.chmod(f"{self.install_path}/start_services.sh", 0o755)
            os.system(f"{self.install_path}/start_services.sh > /dev/null 2>&1")
            time.sleep(10)
            
            # Verify services are running
            self.verify_installation()
        else:
            self.log("Start script not found", Colors.BRIGHT_RED, "ERROR")
            
    def verify_installation(self):
        """Verify that all services are running properly"""
        self.log("Verifying installation...")
        
        # Check processes
        processes = {
            'nginx': f"{self.install_path}/nginx/sbin/nginx",
            'nginx_rtmp': f"{self.install_path}/nginx_rtmp/sbin/nginx_rtmp", 
            'php-fpm': "php-fpm",
            'mariadb': "mysqld"
        }
        
        all_running = True
        for name, process in processes.items():
            if os.system(f"pgrep -f '{process}' > /dev/null") == 0:
                self.log(f"✓ {name} is running", Colors.BRIGHT_GREEN)
            else:
                self.log(f"✗ {name} is not running", Colors.BRIGHT_RED, "ERROR")
                all_running = False
                
        # Check ports
        ports = {25500: 'Admin Panel', 25461: 'Streaming', 25462: 'RTMP', 25463: 'HTTPS'}
        for port, desc in ports.items():
            if os.system(f"netstat -tlnp | grep :{port} > /dev/null") == 0:
                self.log(f"✓ Port {port} ({desc}) is listening", Colors.BRIGHT_GREEN)
            else:
                self.log(f"✗ Port {port} ({desc}) is not listening", Colors.BRIGHT_RED, "ERROR")
                all_running = False
                
        return all_running
        
    def create_credentials_file(self, mysql_password):
        """Create credentials file with all important information"""
        self.log("Creating credentials file...")
        
        credentials = f"""# Xtream UI Installation Credentials
# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}

## Server Information
Server IP: {self.server_ip}
Installation Path: {self.install_path}
Backup Location: {self.backup_dir}

## Database Credentials
MySQL User: user_iptvpro
MySQL Password: {mysql_password}
Database Name: xtream_iptvpro
Database Port: 7999

## Admin Panel Access
Admin Panel URL: http://{self.server_ip}:25500
Default Username: admin
Default Password: admin

## API Endpoints
Streaming Port: 25461
RTMP Port: 25462
HTTPS Port: 25463

## Important Files
Configuration: {self.install_path}/config
Logs Directory: {self.install_path}/logs
Nginx Config: {self.install_path}/nginx/conf/nginx.conf

## System Information
Ubuntu Version: {self.get_os_version()}
Nginx Version: {CONFIG['nginx_version']}
PHP Version: {CONFIG['php_version']}
MariaDB Version: {CONFIG['mariadb_version']}

## Security Information
Firewall: UFW enabled with ports 22, 25500, 25461-25463 open
Fail2ban: Configured for SSH and Nginx protection

## Quick Commands
Start Services: systemctl start xtreamcodes
Stop Services: systemctl stop xtreamcodes  
Restart Services: systemctl restart xtreamcodes
Check Status: systemctl status xtreamcodes

## Troubleshooting
Check Logs: tail -f {self.install_path}/logs/xtreamcodes.log
Check Processes: ps aux | grep -E "(nginx|php-fpm|mysql)"
Check Ports: netstat -tlnp | grep -E "(25500|25461|25462|25463)"
"""
        
        with open("/root/xtream_credentials.txt", "w") as f:
            f.write(credentials)
            
        os.chmod("/root/xtream_credentials.txt", 0o600)
        
    def cleanup(self):
        """Clean up temporary files"""
        self.log("Cleaning up temporary files...")
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        
    def install_main_server(self):
        """Install main server"""
        self.print_banner("Installing Xtream UI Main Server", Colors.BRIGHT_BLUE)
        
        mysql_password = self.generate_password()
        
        # Installation steps
        steps = [
            ("System Requirements Check", self.check_system_requirements),
            ("Backup Existing Installation", self.backup_existing_installation),
            ("Stop Existing Services", self.stop_existing_services),
            ("Prepare System", self.prepare_system),
            ("Setup MariaDB Repository", self.setup_mariadb_repository),
            ("Compile Nginx", self.compile_nginx),
            ("Install PHP & ionCube", self.install_php_ioncube),
            ("Create User & Directories", self.create_user_and_directories),
            ("Download Xtream UI", lambda: self.download_and_install_xtream("MAIN")),
            ("Configure MariaDB", lambda: self.configure_mysql("user_iptvpro", mysql_password)),
            ("Encrypt Configuration", lambda: self.encrypt_config("127.0.0.1", "user_iptvpro", mysql_password, "xtream_iptvpro", 1)),
            ("Configure System", self.configure_system),
            ("Set Permissions", self.set_permissions),
            ("Setup Security", self.setup_security),
            ("Optimize Performance", self.optimize_performance),
            ("Start Services", self.start_services),
            ("Create Credentials File", lambda: self.create_credentials_file(mysql_password)),
            ("Cleanup", self.cleanup)
        ]
        
        os.makedirs(self.temp_dir, exist_ok=True)
        
        for step_name, step_func in steps:
            try:
                self.log(f"Executing: {step_name}")
                step_func()
            except Exception as e:
                self.log(f"Failed at step '{step_name}': {str(e)}", Colors.BRIGHT_RED, "ERROR")
                return False
                
        return True
        
    def install_load_balancer(self, main_ip, mysql_password, server_id):
        """Install load balancer server"""
        self.print_banner("Installing Xtream UI Load Balancer", Colors.BRIGHT_BLUE)
        
        # Similar steps but without MariaDB setup
        steps = [
            ("System Requirements Check", self.check_system_requirements),
            ("Stop Existing Services", self.stop_existing_services),
            ("Prepare System", self.prepare_system),
            ("Compile Nginx", self.compile_nginx),
            ("Install PHP & ionCube", self.install_php_ioncube),
            ("Create User & Directories", self.create_user_and_directories),
            ("Download Xtream UI", lambda: self.download_and_install_xtream("LB")),
            ("Encrypt Configuration", lambda: self.encrypt_config(main_ip, "user_iptvpro", mysql_password, "xtream_iptvpro", server_id)),
            ("Configure System", self.configure_system),
            ("Set Permissions", self.set_permissions),
            ("Setup Security", self.setup_security),
            ("Optimize Performance", self.optimize_performance),
            ("Start Services", self.start_services),
            ("Cleanup", self.cleanup)
        ]
        
        os.makedirs(self.temp_dir, exist_ok=True)
        
        for step_name, step_func in steps:
            try:
                self.log(f"Executing: {step_name}")
                step_func()
            except Exception as e:
                self.log(f"Failed at step '{step_name}': {str(e)}", Colors.BRIGHT_RED, "ERROR")
                return False
                
        return True
        
    def print_final_report(self, install_type, mysql_password=None):
        """Print final installation report"""
        duration = int(time.time() - self.start_time)
        
        report = f"""Installation Complete!

Installation Type: {install_type}
Duration: {duration // 60}m {duration % 60}s
Server IP: {self.server_ip}

Components Installed:
• Nginx {CONFIG['nginx_version']} (compiled from source)
• PHP {CONFIG['php_version']} with ionCube
• MariaDB {CONFIG['mariadb_version']}
• Xtream UI R22F

Access Information:
• Admin Panel: http://{self.server_ip}:25500
• Default Login: admin/admin
• API Port: 25461
"""

        if mysql_password:
            report += f"\nMySQL Password: {mysql_password}"
            
        report += f"""

Credentials saved to: /root/xtream_credentials.txt
Backup location: {self.backup_dir}

Security Features:
• UFW Firewall configured
• Fail2ban protection enabled
• Config file encrypted

Performance Optimizations:
• Kernel parameters tuned
• MySQL optimized for IPTV
• Nginx compiled with performance modules

Quick Commands:
• Start: systemctl start xtreamcodes  
• Stop: systemctl stop xtreamcodes
• Status: systemctl status xtreamcodes
"""
        
        self.print_banner(report, Colors.BRIGHT_GREEN)

def main():
    installer = XtreamInstaller()
    
    installer.print_banner("Xtream UI R22F Advanced Installer v2.0\nUbuntu 20.04/22.04 LTS\nNginx 1.26 • PHP 8.1 • MariaDB 10.11", 
                          Colors.BRIGHT_CYAN, 3)
    
    while True:
        print(f"{Colors.BRIGHT_YELLOW}Installation Options:{Colors.ENDC}")
        print("1. Main Server (Full Installation)")
        print("2. Load Balancer Server") 
        print("3. Exit")
        print()
        
        choice = input("Select option [1-3]: ").strip()
        
        if choice == "1":
            print(f"\n{Colors.BRIGHT_GREEN}Starting Main Server Installation...{Colors.ENDC}")
            if input("Continue? [Y/n]: ").lower() in ['y', 'yes', '']:
                success = installer.install_main_server()
                if success:
                    installer.print_final_report("Main Server", "Check /root/xtream_credentials.txt")
                break
                
        elif choice == "2":
            print(f"\n{Colors.BRIGHT_GREEN}Load Balancer Configuration:{Colors.ENDC}")
            main_ip = input("Main Server IP Address: ").strip()
            mysql_password = input("MySQL Password: ").strip()
            try:
                server_id = int(input("Load Balancer Server ID: ").strip())
            except:
                print("Invalid Server ID")
                continue
                
            if main_ip and mysql_password and server_id > 0:
                if input("Continue? [Y/n]: ").lower() in ['y', 'yes', '']:
                    success = installer.install_load_balancer(main_ip, mysql_password, server_id)
                    if success:
                        installer.print_final_report("Load Balancer")
                    break
            else:
                print("Invalid configuration")
                
        elif choice == "3":
            print("Installation cancelled")
            break
        else:
            print("Invalid option")

if __name__ == "__main__":
    main()

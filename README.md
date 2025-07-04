# 🐉 Dragon Shield 2025 - Xtream UI Advanced Installer

[![GitHub release](https://img.shields.io/github/release/Stefan2512/dragon-shield2025.svg)](https://github.com/Stefan2512/dragon-shield2025/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%20|%2022.04-orange.svg)](https://ubuntu.com/)
[![Python](https://img.shields.io/badge/Python-3.8+-green.svg)](https://python.org/)

> **🚀 Next-Generation Xtream UI Installer with Modern Components**

Advanced, secure, and optimized installer for Xtream UI R22F with cutting-edge components and enterprise-grade security features.

## ✨ Features

### 🔧 **Modern Components**
- **Nginx 1.26** - Latest stable, compiled from source with performance modules
- **PHP 8.1** - Modern PHP with optimized ionCube Loader
- **MariaDB 10.11 LTS** - Latest long-term support with IPTV optimizations
- **Systemd Integration** - Proper service management and auto-restart

### 🛡️ **Enterprise Security**
- **UFW Firewall** - Automatically configured with essential ports
- **Fail2ban Protection** - SSH and Nginx brute-force protection
- **Config Encryption** - Enhanced database credential protection
- **Kernel Hardening** - Performance and security optimizations

### ⚡ **Performance Optimizations**
- **Streaming-Optimized Kernel** - Tuned network parameters
- **MySQL Performance Tuning** - IPTV-specific database optimizations
- **tmpfs for Streams** - RAM-based temporary storage for better performance
- **BBR Congestion Control** - Modern TCP optimization

### 🔄 **Advanced Installation Features**
- **Pre-Installation Checks** - System requirements validation
- **Automatic Backup** - Existing installation backup before upgrade
- **Real-time Monitoring** - Installation progress with detailed logging
- **Service Verification** - Automatic health checks post-installation
- **Comprehensive Reporting** - Detailed installation summary and credentials

## 📋 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | Ubuntu 20.04 LTS | Ubuntu 22.04 LTS |
| **RAM** | 2GB | 8GB+ |
| **Storage** | 10GB | 50GB+ SSD |
| **Network** | 100Mbps | 1Gbps+ |
| **CPU** | 2 cores | 4+ cores |

### 🖥️ **Supported Platforms**
- ✅ Ubuntu 20.04 LTS (Focal Fossa)
- ✅ Ubuntu 22.04 LTS (Jammy Jellyfish)
- ✅ VPS/Dedicated Servers
- ✅ Cloud Instances (AWS, DigitalOcean, etc.)

## 🚀 Quick Start

### 1️⃣ **Download & Execute**

```bash
# Download the installer
wget https://raw.githubusercontent.com/Stefan2512/dragon-shield2025/main/install.py

# Make it executable and run
chmod +x install.py
sudo python3 install.py
```

### 2️⃣ **Installation Options**

The installer will present you with these options:

```
🐉 Dragon Shield 2025 - Installation Options:

1. Main Server (Full Installation)
   └── Complete Xtream UI setup with database
   
2. Load Balancer Server
   └── Additional streaming server setup
   
3. Exit
```

### 3️⃣ **Main Server Installation**

For a complete installation, select option **1**:

- ✅ Automatically installs all components
- ✅ Creates optimized database
- ✅ Configures security measures
- ✅ Sets up monitoring and logging
- ✅ Generates admin credentials

### 4️⃣ **Load Balancer Setup**

For additional streaming servers, select option **2** and provide:

- **Main Server IP**: Your primary server's IP address
- **MySQL Password**: Database password from main server
- **Server ID**: Unique identifier for this load balancer

## 🔧 Configuration

### 📊 **Default Access Points**

| Service | URL/Port | Description |
|---------|----------|-------------|
| **Admin Panel** | `http://YOUR_IP:25500` | Web management interface |
| **Streaming API** | `http://YOUR_IP:25461` | Main streaming endpoint |
| **RTMP** | `rtmp://YOUR_IP:25462` | Real-time streaming |
| **HTTPS** | `https://YOUR_IP:25463` | Secure streaming |

### 🔑 **Default Credentials**

```
Username: admin
Password: admin
```

> ⚠️ **Important**: Change default credentials immediately after first login!

### 📁 **Important Directories**

```bash
# Main installation
/home/xtreamcodes/iptv_xtream_codes/

# Configuration files
/home/xtreamcodes/iptv_xtream_codes/config

# Log files
/home/xtreamcodes/iptv_xtream_codes/logs/

# Streaming cache (tmpfs)
/home/xtreamcodes/iptv_xtream_codes/streams/
```

## 🛠️ Management Commands

### 🔄 **Service Control**

```bash
# Start services
sudo systemctl start xtreamcodes

# Stop services  
sudo systemctl stop xtreamcodes

# Restart services
sudo systemctl restart xtreamcodes

# Check status
sudo systemctl status xtreamcodes

# Enable auto-start
sudo systemctl enable xtreamcodes
```

### 📊 **Monitoring**

```bash
# Check running processes
ps aux | grep -E "(nginx|php-fpm|mysql)"

# Check open ports
netstat -tlnp | grep -E "(25500|25461|25462|25463)"

# View logs
tail -f /home/xtreamcodes/iptv_xtream_codes/logs/xtreamcodes.log

# Check system resources
htop
```

### 🔍 **Database Access**

```bash
# Connect to database
mysql -u user_iptvpro -p -P 7999 xtream_iptvpro

# Check database status
systemctl status mariadb
```

## 🆘 Troubleshooting

### 🚨 **Common Issues**

<details>
<summary><strong>Services not starting</strong></summary>

1. Check system requirements:
   ```bash
   df -h  # Check disk space
   free -h  # Check RAM
   ```

2. Verify permissions:
   ```bash
   sudo chown -R xtreamcodes:xtreamcodes /home/xtreamcodes/
   sudo chmod +x /home/xtreamcodes/iptv_xtream_codes/*.sh
   ```

3. Check logs:
   ```bash
   tail -f /home/xtreamcodes/iptv_xtream_codes/logs/xtreamcodes.log
   journalctl -u xtreamcodes -f
   ```
</details>

<details>
<summary><strong>Database connection errors</strong></summary>

1. Verify MariaDB is running:
   ```bash
   sudo systemctl status mariadb
   sudo systemctl restart mariadb
   ```

2. Check database configuration:
   ```bash
   mysql -u root -e "SHOW DATABASES;"
   mysql -u user_iptvpro -p -P 7999
   ```

3. Reset database password if needed:
   ```bash
   sudo mysql -u root -e "ALTER USER 'user_iptvpro'@'%' IDENTIFIED BY 'new_password';"
   ```
</details>

<details>
<summary><strong>Admin panel not accessible</strong></summary>

1. Check if Nginx is running:
   ```bash
   sudo netstat -tlnp | grep :25500
   ps aux | grep nginx
   ```

2. Verify firewall settings:
   ```bash
   sudo ufw status
   sudo ufw allow 25500
   ```

3. Check Nginx configuration:
   ```bash
   sudo nginx -t
   tail -f /home/xtreamcodes/iptv_xtream_codes/nginx/logs/error.log
   ```
</details>

### 🔧 **Repair & Recovery**

If you encounter issues, the installer includes built-in repair functionality:

```bash
# Re-run installer to repair
sudo python3 install.py

# Manual service restart
sudo /home/xtreamcodes/iptv_xtream_codes/start_services.sh

# Reset permissions
sudo chown -R xtreamcodes:xtreamcodes /home/xtreamcodes/
```

## 📈 Performance Tuning

### 🎛️ **System Optimizations**

The installer automatically applies these optimizations:

- **Network Buffers**: Increased for high-bandwidth streaming
- **TCP Congestion Control**: BBR algorithm for better throughput  
- **File Descriptors**: Increased limits for concurrent connections
- **MySQL**: Optimized for IPTV workloads
- **tmpfs**: RAM-based storage for temporary files

### 📊 **Monitoring Performance**

```bash
# Check network usage
iftop

# Monitor system resources
htop

# Check MySQL performance
mysql -u root -e "SHOW GLOBAL STATUS LIKE 'Threads_connected';"

# Monitor streaming connections
netstat -an | grep :25461 | wc -l
```

## 🔐 Security Features

### 🛡️ **Built-in Security**

- **UFW Firewall**: Only essential ports open
- **Fail2ban**: Automatic IP blocking for suspicious activity
- **Encrypted Configuration**: Database credentials protected
- **Kernel Hardening**: Security-focused system parameters
- **User Isolation**: Dedicated xtreamcodes user account

### 🔒 **Security Best Practices**

1. **Change Default Passwords**:
   ```bash
   # Admin panel: Change via web interface
   # Database: mysql -u root -e "ALTER USER 'user_iptvpro'@'%' IDENTIFIED BY 'strong_password';"
   ```

2. **Regular Updates**:
   ```bash
   sudo apt update && sudo apt upgrade
   ```

3. **Monitor Logs**:
   ```bash
   tail -f /var/log/auth.log
   tail -f /var/log/fail2ban.log
   ```

## 📦 What's Included

### 📋 **Installation Components**

- ✅ **Nginx 1.26** - High-performance web server
- ✅ **PHP 8.1 + ionCube** - Modern PHP runtime
- ✅ **MariaDB 10.11** - Reliable database server
- ✅ **FFmpeg** - Media processing
- ✅ **Xtream UI R22F** - Complete IPTV panel
- ✅ **Security Tools** - UFW, Fail2ban
- ✅ **Monitoring Tools** - System health checks

### 📁 **Generated Files**

After installation, you'll find:

- 📄 `/root/xtream_credentials.txt` - All login credentials
- 🔧 `/etc/systemd/system/xtreamcodes.service` - System service
- 🛡️ `/etc/fail2ban/jail.local` - Security configuration
- ⚡ `/etc/sysctl.d/99-xtream-performance.conf` - Performance tuning

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### 🐛 **Bug Reports**

1. Check existing [issues](https://github.com/Stefan2512/dragon-shield2025/issues)
2. Create detailed bug report with:
   - OS version and details
   - Error messages
   - Steps to reproduce
   - Log files

### 💡 **Feature Requests**

1. Open an [issue](https://github.com/Stefan2512/dragon-shield2025/issues/new)
2. Describe the feature and use case
3. Provide implementation suggestions if possible

### 🔧 **Pull Requests**

1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit pull request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### 💬 **Get Help**

- 📧 **Email**: Stefan@outlook.ie
- 🐛 **Issues**: [GitHub Issues](https://github.com/Stefan2512/dragon-shield2025/issues)
- 📖 **Documentation**: [Wiki](https://github.com/Stefan2512/dragon-shield2025/wiki)

### 🌟 **Show Your Support**

If this project helped you, please consider:

- ⭐ **Star this repository**
- 🍴 **Fork and contribute**
- 📢 **Share with others**
- 💰 **[Sponsor the project](https://github.com/sponsors/Stefan2512)**

## 📊 Project Stats

![GitHub stars](https://img.shields.io/github/stars/Stefan2512/dragon-shield2025?style=social)
![GitHub forks](https://img.shields.io/github/forks/Stefan2512/dragon-shield2025?style=social)
![GitHub issues](https://img.shields.io/github/issues/Stefan2512/dragon-shield2025)
![GitHub last commit](https://img.shields.io/github/last-commit/Stefan2512/dragon-shield2025)

---

<div align="center">

**🐉 Dragon Shield 2025 - Powering the Future of IPTV**

Made with ❤️ by [Stefan2512](https://github.com/Stefan2512)

[⬆ Back to Top](#-dragon-shield-2025---xtream-ui-advanced-installer)

</div>

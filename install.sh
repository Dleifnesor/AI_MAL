#!/bin/bash
# Installation script for AI_MAL
# This script installs dependencies and sets up the environment

# Exit on any error
set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Version
VERSION="1.0.0"

# Function to check if running with sudo
check_sudo() {
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}This script needs to be run with sudo privileges${NC}"
        echo -e "    Please run: ${GREEN}sudo ./install.sh${NC}"
        exit 1
    fi
}

# Check for sudo privileges
check_sudo

# Determine the installation directory (where the script is located)
INSTALL_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$INSTALL_DIR" || { echo "Could not change to install directory"; exit 1; }

# Print welcome message
echo "====================================================="
echo "       Installing AI_MAL - AI-Powered Penetration Testing Tool"
echo "====================================================="
echo

# Function to check if a command exists
command_exists() {
    command -v "$1" > /dev/null 2>&1
}

# Function to check system type
get_system_type() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Function to check Linux distribution
get_linux_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/redhat-release ]; then
        echo "redhat"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

# Check for essential system dependencies
echo -e "${YELLOW}[+] Checking essential system dependencies...${NC}"
MISSING_DEPS=()
ESSENTIAL_DEPS=(
    "curl" 
    "git" 
    "python3" 
    "python3-pip" 
    "python3-venv" 
    "gcc" 
    "python3-dev" 
    "libpq-dev" 
    "libffi-dev" 
    "bc"
    "smbclient"
    "libsmbclient-dev"
    "build-essential"
    "libssl-dev"
    "libffi-dev"
    "python3-dev"
    "libxml2-dev"
    "libxslt1-dev"
    "zlib1g-dev"
    "libncurses5-dev"
    "libncursesw5-dev"
    "libreadline-dev"
    "libsqlite3-dev"
    "libbz2-dev"
    "libexpat1-dev"
    "liblzma-dev"
    "libgdbm-dev"
    "libuuid1"
    "uuid-dev"
    "libgmp-dev"
    "libmpfr-dev"
    "libmpc-dev"
    "libldap2-dev"
    "libsasl2-dev"
    "libkrb5-dev"
    "libssl-dev"
    "libtls-dev"
    "libgnutls28-dev"
    "libsasl2-modules"
    "libsasl2-modules-gssapi-mit"
    "libsasl2-modules-ldap"
    "libsasl2-modules-otp"
    "libsasl2-modules-sql"
)

# Determine package manager based on system
if command_exists apt-get; then
    PKG_MANAGER="apt-get"
    UPDATE_CMD="apt-get update"
    INSTALL_CMD="apt-get install -y"
elif command_exists yum; then
    PKG_MANAGER="yum"
    UPDATE_CMD="yum update -y"
    INSTALL_CMD="yum install -y"
elif command_exists dnf; then
    PKG_MANAGER="dnf"
    UPDATE_CMD="dnf update -y"
    INSTALL_CMD="dnf install -y"
elif command_exists pacman; then
    PKG_MANAGER="pacman"
    UPDATE_CMD="pacman -Syu --noconfirm"
    INSTALL_CMD="pacman -S --noconfirm"
elif command_exists brew; then
    PKG_MANAGER="brew"
    UPDATE_CMD="brew update"
    INSTALL_CMD="brew install"
else
    echo -e "${RED}Could not determine package manager. Please install dependencies manually.${NC}"
    exit 1
fi

# Install dependencies based on package manager
for dep in "${ESSENTIAL_DEPS[@]}"; do
    if ! command_exists "$dep"; then
        MISSING_DEPS+=("$dep")
    fi
done

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    echo -e "${RED}[!] Installing missing dependencies: ${MISSING_DEPS[*]}${NC}"
    eval "$UPDATE_CMD"
    eval "$INSTALL_CMD ${MISSING_DEPS[*]}" || {
        echo -e "${RED}[-] Failed to install dependencies. Please install them manually:${NC}"
        echo -e "    ${GREEN}sudo $INSTALL_CMD ${MISSING_DEPS[*]}${NC}"
        exit 1
    }
fi

# Check for Python 3
if ! command_exists python3; then
    echo -e "${RED}Python 3 is not installed. Please install Python 3 and try again.${NC}"
    exit 1
fi

# Check Python version (using python3 -c instead of bc)
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo -e "${GREEN}[+] Python version $PYTHON_VERSION is compatible${NC}"
else
    echo -e "${RED}Python 3.8 or higher is required. Current version: $PYTHON_VERSION${NC}"
    exit 1
fi

# Ensure pip is available and up to date
echo -e "${YELLOW}[+] Ensuring pip is available and up to date...${NC}"
if ! command_exists pip3; then
    echo -e "${RED}[!] pip3 not found. Installing python3-pip...${NC}"
    sudo apt-get update
    sudo apt-get install -y python3-pip
fi

# Function to install dos2unix based on the package manager
install_dos2unix() {
    if command_exists apt-get; then
        sudo apt-get update && sudo apt-get install -y dos2unix
    elif command_exists yum; then
        sudo yum install -y dos2unix
    elif command_exists dnf; then
        sudo dnf install -y dos2unix
    elif command_exists pacman; then
        sudo pacman -S --noconfirm dos2unix
    elif command_exists brew; then
        brew install dos2unix
    else
        echo -e "${RED}[-] Could not determine package manager. Please install dos2unix manually.${NC}"
        return 1
    fi
    return 0
}

# Check and install dos2unix
echo -e "${YELLOW}[+] Checking for dos2unix...${NC}"
if ! command_exists dos2unix; then
    echo -e "${RED}[!] dos2unix is not installed. Attempting to install...${NC}"
    if ! install_dos2unix; then
        echo -e "${RED}[-] Failed to install dos2unix. Will try to fix line endings manually.${NC}"
    fi
fi

# Fix line endings in all script files
echo -e "${YELLOW}[+] Fixing line endings in script files...${NC}"
fix_line_endings() {
    local file="$1"
    if command_exists dos2unix; then
        dos2unix "$file"
    else
        # Manual line ending fix using sed
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS version of sed requires different syntax
            sed -i '' 's/\r$//' "$file"
        else
            sed -i 's/\r$//' "$file"
        fi
    fi
}

# Find and fix all Python and shell scripts
echo -e "${YELLOW}[+] Processing script files...${NC}"
while IFS= read -r -d '' file; do
    echo -e "    Fixing line endings in: $file${NC}"
    fix_line_endings "$file"
done < <(find "$INSTALL_DIR" -type f \( -name "*.py" -o -name "*.sh" -o -name "AI_MAL" \) -print0)

# Verify the files are executable and have correct line endings
echo -e "${YELLOW}[+] Verifying file permissions and line endings...${NC}"
for file in "$INSTALL_DIR/AI_MAL" "$INSTALL_DIR/adaptive_nmap_scan.py"; do
    if [ -f "$file" ]; then
        # Make executable
        chmod +x "$file"
        # Double-check line endings
        fix_line_endings "$file"
        echo -e "    Verified: $file${NC}"
    else
        echo -e "${RED}[!] Warning: Could not find $file${NC}"
    fi
done

# Create a virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}[+] Creating virtual environment...${NC}"
    python3 -m venv venv || { echo -e "${RED}Failed to create virtual environment${NC}"; exit 1; }
fi

# Create the virtual environment activation wrapper script
echo -e "${YELLOW}[+] Creating virtual environment wrapper script...${NC}"
cat > "$INSTALL_DIR/ai-mal-env" << 'EOF'
#!/bin/bash
# Activate the virtual environment and run any specified command

# Determine script location
INSTALL_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Source the virtual environment
source "$INSTALL_DIR/venv/bin/activate"

# Execute the command with arguments
exec "$@"
EOF

# Fix line endings in the wrapper script and make it executable
if command_exists dos2unix; then
    dos2unix "$INSTALL_DIR/ai-mal-env"
else
    sed -i 's/\r$//' "$INSTALL_DIR/ai-mal-env"
fi
chmod +x "$INSTALL_DIR/ai-mal-env"

# Activate the virtual environment
echo -e "${YELLOW}[+] Activating virtual environment...${NC}"
source venv/bin/activate || { echo -e "${RED}Failed to activate virtual environment${NC}"; exit 1; }

# Install Python packages in the virtual environment
echo -e "${YELLOW}[+] Installing Python dependencies...${NC}"
python3 -m pip install --upgrade pip

# Install packages in specific order to handle dependencies
echo -e "${YELLOW}[+] Installing core dependencies...${NC}"
python3 -m pip install --upgrade \
    requests \
    pymetasploit3 \
    psutil \
    netifaces \
    paramiko \
    scapy \
    h2 \
    mysql-connector-python \
    python-nmap \
    colorama \
    tqdm \
    cryptography \
    pyOpenSSL \
    dnspython \
    python-whois \
    || { echo -e "${RED}Failed to install core dependencies${NC}"; exit 1; }

# Install python-ldap separately with proper error handling
echo -e "${YELLOW}[+] Installing python-ldap...${NC}"
python3 -m pip install --upgrade python-ldap || {
    echo -e "${RED}Failed to install python-ldap from PyPI, trying alternative method...${NC}"
    # Try installing from system package
    if command_exists apt-get; then
        sudo apt-get install -y python3-ldap || {
            echo -e "${RED}Failed to install python-ldap system package${NC}"
            echo -e "${YELLOW}Continuing without LDAP support...${NC}"
        }
    fi
}

# Install remaining packages
echo -e "${YELLOW}[+] Installing remaining dependencies...${NC}"
python3 -m pip install --upgrade \
    impacket \
    pyasn1 \
    pycryptodomex \
    pymysql \
    pymongo \
    redis \
    elasticsearch \
    beautifulsoup4 \
    lxml \
    python-dateutil \
    pytz \
    pyyaml \
    jinja2 \
    markdown \
    rich \
    prompt-toolkit \
    click \
    tabulate \
    || { echo -e "${RED}Failed to install remaining dependencies${NC}"; exit 1; }

# Install smbclient Python package after system dependencies
echo -e "${YELLOW}[+] Installing smbclient Python package...${NC}"
python3 -m pip install --upgrade smbclient || {
    echo -e "${RED}Failed to install smbclient Python package${NC}"
    echo -e "${YELLOW}Trying alternative installation method...${NC}"
    # Try installing from source
    git clone https://github.com/samba-team/samba.git
    cd samba
    ./configure
    make
    cd ..
    python3 -m pip install ./samba/python/smbclient || {
        echo -e "${RED}Failed to install smbclient from source${NC}"
        echo -e "${YELLOW}Continuing without smbclient support...${NC}"
    }
}

# Check if nmap is installed
echo -e "${YELLOW}[+] Checking for system dependencies...${NC}"
if ! command_exists nmap; then
    echo -e "${RED}[!] nmap is not installed. Attempting to install...${NC}"
    
    # Check the package manager and install nmap
    if command_exists apt-get; then
        sudo apt-get update
        sudo apt-get install -y nmap || { echo -e "${RED}Failed to install nmap${NC}"; exit 1; }
    elif command_exists yum; then
        sudo yum install -y nmap || { echo -e "${RED}Failed to install nmap${NC}"; exit 1; }
    elif command_exists dnf; then
        sudo dnf install -y nmap || { echo -e "${RED}Failed to install nmap${NC}"; exit 1; }
    elif command_exists pacman; then
        sudo pacman -S --noconfirm nmap || { echo -e "${RED}Failed to install nmap${NC}"; exit 1; }
    elif command_exists brew; then
        brew install nmap || { echo -e "${RED}Failed to install nmap${NC}"; exit 1; }
    else
        echo -e "${RED}[-] Could not determine package manager. Please install nmap manually.${NC}"
        exit 1
    fi
fi

# Install additional system dependencies for Nmap
echo -e "${YELLOW}[+] Installing additional Nmap dependencies...${NC}"
if command_exists apt-get; then
    sudo apt-get install -y libpcap-dev libssl-dev libffi-dev || { echo -e "${RED}Failed to install Nmap dependencies${NC}"; exit 1; }
elif command_exists yum; then
    sudo yum install -y libpcap-devel openssl-devel libffi-devel || { echo -e "${RED}Failed to install Nmap dependencies${NC}"; exit 1; }
elif command_exists dnf; then
    sudo dnf install -y libpcap-devel openssl-devel libffi-devel || { echo -e "${RED}Failed to install Nmap dependencies${NC}"; exit 1; }
elif command_exists pacman; then
    sudo pacman -S --noconfirm libpcap openssl libffi || { echo -e "${RED}Failed to install Nmap dependencies${NC}"; exit 1; }
fi

# Create Nmap output filter script
echo -e "${YELLOW}[+] Creating Nmap output filter script...${NC}"
cat > "$INSTALL_DIR/nmap_filter.py" << 'EOF'
#!/usr/bin/env python3
import sys
import re

def filter_nmap_output(line):
    # Skip debug messages
    if any(debug in line.lower() for debug in ['debug:', 'debugging:', 'debugger:']):
        return False
    
    # Skip verbose output
    if any(verbose in line.lower() for verbose in ['verbose:', 'verbosity:', 'verbose output:']):
        return False
    
    # Skip timing messages
    if any(timing in line.lower() for timing in ['timing:', 'timing report:', 'scan timing:']):
        return False
    
    # Skip statistics
    if any(stat in line.lower() for stat in ['statistics:', 'stats:', 'scan stats:']):
        return False
    
    # Skip progress messages
    if any(progress in line.lower() for progress in ['progress:', 'scanning:', 'scan progress:']):
        return False
    
    # Skip system messages
    if any(system in line.lower() for system in ['system:', 'system info:', 'system details:']):
        return False
    
    # Skip version messages
    if any(version in line.lower() for version in ['version:', 'version info:', 'version details:']):
        return False
    
    # Skip warning messages unless they're critical
    if 'warning:' in line.lower() and not any(critical in line.lower() for critical in ['critical', 'error', 'failed']):
        return False
    
    # Skip info messages unless they're important
    if 'info:' in line.lower() and not any(important in line.lower() for important in ['critical', 'error', 'failed', 'open', 'closed', 'filtered']):
        return False
    
    return True

def main():
    for line in sys.stdin:
        if filter_nmap_output(line):
            sys.stdout.write(line)
            sys.stdout.flush()

if __name__ == '__main__':
    main()
EOF

# Make the filter script executable
chmod +x "$INSTALL_DIR/nmap_filter.py"

# Update the Python script to use the filter
echo -e "${YELLOW}[+] Updating Python script to use Nmap filter...${NC}"
sed -i 's/subprocess.run(/subprocess.Popen([/g' "$INSTALL_DIR/adaptive_nmap_scan.py"
sed -i 's/], capture_output=True, text=True, errors="replace")/], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")/g' "$INSTALL_DIR/adaptive_nmap_scan.py"
sed -i 's/result.stdout/result.stdout.decode("utf-8", errors="replace")/g' "$INSTALL_DIR/adaptive_nmap_scan.py"
sed -i 's/result.stderr/result.stderr.decode("utf-8", errors="replace")/g' "$INSTALL_DIR/adaptive_nmap_scan.py"

# Add filter to the command
sed -i 's/command = \[/command = ["python3", "'"$INSTALL_DIR"'/nmap_filter.py", "|", /g' "$INSTALL_DIR/adaptive_nmap_scan.py"

# Verify nmap installation
if command_exists nmap; then
    NMAP_VERSION=$(nmap --version | head -n 1)
    echo -e "${GREEN}[+] Found $NMAP_VERSION${NC}"
    echo -e "${GREEN}[+] AI_MAL will use system nmap via subprocess${NC}"
else
    echo -e "${RED}[-] nmap is not installed. Please install it manually.${NC}"
    exit 1
fi

# Check for Metasploit Framework
echo -e "${YELLOW}[+] Checking for Metasploit Framework...${NC}"
if ! command_exists msfconsole; then
    echo -e "${RED}[!] Metasploit Framework not found. Attempting to install...${NC}"
    if command_exists apt-get; then
        sudo apt-get update
        sudo apt-get install -y metasploit-framework postgresql
    else
        echo -e "${RED}[!] Metasploit Framework not found. MSF integration will not be available.${NC}"
        echo -e "    To install Metasploit Framework, follow instructions at:${NC}"
        echo -e "    ${GREEN}https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html${NC}"
    fi
fi

# Set up PostgreSQL for Metasploit with improved error handling
echo -e "${YELLOW}[+] Setting up PostgreSQL for Metasploit...${NC}"
setup_postgresql() {
    local max_retries=30
    local retry_count=1
    
    if command_exists psql; then
        # Ensure PostgreSQL is installed and running
        if ! command_exists systemctl || ! systemctl is-active --quiet postgresql; then
            echo -e "${RED}[!] Starting PostgreSQL service...${NC}"
            if command_exists systemctl; then
                # First enable the service
                sudo systemctl enable postgresql || {
                    echo -e "${RED}[!] Failed to enable PostgreSQL service${NC}"
                    return 1
                }
                
                # Then start the service
                sudo systemctl start postgresql || {
                    echo -e "${RED}[!] Failed to start PostgreSQL with systemctl, trying service command...${NC}"
                    sudo service postgresql start
                }
                
                # Verify the service is running
                if ! systemctl is-active --quiet postgresql; then
                    echo -e "${RED}[!] PostgreSQL service is not running after start attempt${NC}"
                    return 1
                fi
            else
                sudo service postgresql start
            fi
            
            # Wait for PostgreSQL to start with timeout
            echo -e "${GREEN}[+] Waiting for PostgreSQL to start...${NC}"
            while [ $retry_count -le $max_retries ]; do
                if pg_isready -q; then
                    echo -e "${GREEN}[+] PostgreSQL is ready${NC}"
                    break
                fi
                echo -n "."
                sleep 1
                retry_count=$((retry_count + 1))
            done
            
            if [ $retry_count -gt $max_retries ]; then
                echo -e "${RED}[-] PostgreSQL failed to start within $max_retries seconds${NC}"
                # Try to get more information about the failure
                if command_exists systemctl; then
                    echo -e "${RED}[!] PostgreSQL service status:${NC}"
                    systemctl status postgresql | cat
                fi
                if [ -f /var/log/postgresql/postgresql-*.log ]; then
                    echo -e "${RED}[!] Last few lines of PostgreSQL log:${NC}"
                    tail -n 20 /var/log/postgresql/postgresql-*.log
                fi
                return 1
            fi
        fi
        
        # Initialize Metasploit database with proper error handling
        echo -e "${GREEN}[+] Initializing Metasploit database...${NC}"
        if command_exists msfdb; then
            if ! sudo msfdb init; then
                echo -e "${RED}[!] msfdb init failed, trying alternative setup...${NC}"
                
                # Create msf user and database with proper error handling
                if ! sudo -u postgres psql -c "CREATE USER msf WITH PASSWORD 'msf';" 2>/dev/null; then
                    echo -e "${RED}[!] User msf might already exist, continuing...${NC}"
                fi
                
                if ! sudo -u postgres psql -c "CREATE DATABASE msf OWNER msf;" 2>/dev/null; then
                    echo -e "${RED}[!] Database msf might already exist, continuing...${NC}"
                fi
                
                if ! sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE msf TO msf;" 2>/dev/null; then
                    echo -e "${RED}[!] Failed to grant privileges, continuing...${NC}"
                fi
                
                # Create database.yml with proper permissions
                MSF_CONFIG_DIR="$HOME/.msf4"
                mkdir -p "$MSF_CONFIG_DIR"
                cat << 'EOF' > "$MSF_CONFIG_DIR/database.yml"
production:
  adapter: postgresql
  database: msf
  username: msf
  password: msf
  host: localhost
  port: 5432
  pool: 5
  timeout: 5
EOF
                
                chmod 600 "$MSF_CONFIG_DIR/database.yml"
            fi
        fi
    else
        echo -e "${RED}[!] PostgreSQL not found. Installing...${NC}"
        if command_exists apt-get; then
            sudo apt-get update
            sudo apt-get install -y postgresql postgresql-contrib
            
            # Enable and start PostgreSQL after installation
            if command_exists systemctl; then
                sudo systemctl enable postgresql
                sudo systemctl start postgresql
                
                # Verify the service is running
                if ! systemctl is-active --quiet postgresql; then
                    echo -e "${RED}[!] PostgreSQL service is not running after installation${NC}"
                    return 1
                fi
            else
                sudo service postgresql start
            fi
            
            # Retry database initialization with timeout
            echo -e "${GREEN}[+] Retrying Metasploit database initialization...${NC}"
            if command_exists msfdb; then
                if ! sudo msfdb init; then
                    echo -e "${RED}[-] Failed to initialize Metasploit database${NC}"
                    return 1
                fi
            fi
        else
            echo -e "${RED}[-] PostgreSQL installation failed. Metasploit will run without database support.${NC}"
            return 1
        fi
    fi
    return 0
}

# Run PostgreSQL setup
if ! setup_postgresql; then
    echo -e "${RED}[!] Warning: Metasploit database setup completed with errors${NC}"
    echo -e "    Some features may be limited${NC}"
fi

# Function to install Ollama
install_ollama() {
    echo -e "${YELLOW}[+] Installing Ollama...${NC}"
    
    # Check if Ollama is already installed
    if command_exists ollama; then
        echo -e "${GREEN}[+] Ollama is already installed${NC}"
        return 0
    fi
    
    # Download and install Ollama
    echo -e "${YELLOW}[+] Downloading Ollama...${NC}"
    curl -fsSL https://ollama.com/install.sh | sudo sh || {
        echo -e "${RED}[-] Failed to install Ollama${NC}"
        return 1
    }
    
    # Verify installation
    if ! command_exists ollama; then
        echo -e "${RED}[-] Ollama installation failed${NC}"
        return 1
    fi
    
    # Start Ollama service
    echo -e "${YELLOW}[+] Starting Ollama service...${NC}"
    if command_exists systemctl; then
        sudo systemctl enable ollama
        sudo systemctl start ollama
    else
        nohup ollama serve > /var/log/ollama.log 2>&1 &
    fi
    
    # Wait for Ollama to be ready
    echo -e "${GREEN}[+] Waiting for Ollama to start...${NC}"
    for i in {1..30}; do
        if curl -s http://localhost:11434/api/version > /dev/null; then
            echo -e "${GREEN}[+] Ollama is ready${NC}"
            break
        fi
        echo -n "."
        sleep 1
        if [ $i -eq 30 ]; then
            echo -e "${RED}[-] Ollama failed to start within 30 seconds${NC}"
            return 1
        fi
    done
    
    # Pull required models
    echo -e "${YELLOW}[+] Pulling required models...${NC}"
    local models=("codellama" "gemma3:1b" "qwen2.5-coder:7b")
    for model in "${models[@]}"; do
        echo -e "${YELLOW}[+] Pulling model: $model${NC}"
        if ! ollama pull "$model"; then
            echo -e "${RED}[!] Warning: Failed to pull model: $model${NC}"
            echo -e "    Some features may be limited${NC}"
        fi
    done
    
    return 0
}

# Install Ollama
if ! install_ollama; then
    echo -e "${RED}[!] Warning: Ollama installation completed with errors${NC}"
    echo -e "    Some features may be limited${NC}"
fi

# Make the main files executable
echo -e "${GREEN}[+] Setting executable permissions...${NC}"
chmod +x "$INSTALL_DIR/AI_MAL"

# Create a symbolic link to the AI_MAL script in /usr/local/bin if possible
if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
    echo -e "${GREEN}[+] Creating symlink in /usr/local/bin...${NC}"
    ln -sf "$INSTALL_DIR/AI_MAL" /usr/local/bin/AI_MAL
    echo -e "${GREEN}[+] AI_MAL installed system-wide. You can run it from any directory with 'AI_MAL'${NC}"
else
    echo -e "${RED}[!] Could not create symlink in /usr/local/bin (permission denied)${NC}"
    echo -e "    You can run AI_MAL from this directory with './AI_MAL'${NC}"
fi

# Final success message
echo
echo "====================================================="
echo "       AI_MAL Installation Complete"
echo "====================================================="
echo
echo "Examples:"
echo "  # Basic scan of a target"
echo "  AI_MAL 192.168.1.1"
echo
echo "  # Auto-discover hosts and scan with stealth mode"
echo "  AI_MAL --auto-discover --stealth"
echo
echo "  # Use gemma3:1b model for systems with less than 4GB RAM"
echo "  AI_MAL --model gemma3:1b --stealth"
echo
echo "  # Full integration with Metasploit"
echo "  AI_MAL 192.168.1.1 --msf --exploit"
echo
echo "Read the documentation for more information."
echo "For help, run: AI_MAL --help"
echo

# Function to handle errors and cleanup
handle_error() {
    local exit_code=$1
    local error_message=$2
    
    echo -e "${RED}[-] Error: $error_message${NC}"
    echo -e "    Exit code: $exit_code${NC}"
    
    # Cleanup temporary files
    if [ -f "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
    
    # Stop services if they were started
    if command_exists systemctl; then
        sudo systemctl stop ollama 2>/dev/null || true
        sudo systemctl stop postgresql 2>/dev/null || true
    else
        sudo service ollama stop 2>/dev/null || true
        sudo service postgresql stop 2>/dev/null || true
    fi
    
    # Exit with error code
    exit "$exit_code"
}

# Function to cleanup on script exit
cleanup() {
    local exit_code=$?
    
    # Cleanup temporary files
    if [ -f "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
    
    # Stop services if they were started
    if command_exists systemctl; then
        sudo systemctl stop ollama 2>/dev/null || true
        sudo systemctl stop postgresql 2>/dev/null || true
    else
        sudo service ollama stop 2>/dev/null || true
        sudo service postgresql stop 2>/dev/null || true
    fi
    
    # Exit with original exit code
    exit "$exit_code"
}

# Set up trap for cleanup on script exit
trap cleanup EXIT

# Create temporary directory for installation
TEMP_DIR=$(mktemp -d)
if [ ! -d "$TEMP_DIR" ]; then
    handle_error 1 "Failed to create temporary directory"
fi

# Function to check network connectivity
check_network() {
    local max_retries=3
    local retry_count=1
    
    echo -e "${GREEN}[+] Checking network connectivity...${NC}"
    while [ $retry_count -le $max_retries ]; do
        if curl -s https://www.google.com > /dev/null; then
            echo -e "${GREEN}[+] Network connection verified${NC}"
            return 0
        fi
        echo -e "${RED}[!] Network connection failed (attempt $retry_count/$max_retries)${NC}"
        retry_count=$((retry_count + 1))
        sleep 2
    done
    
    handle_error 1 "Network connection failed after $max_retries attempts"
}

# Check network connectivity before proceeding
check_network

# Function to verify disk space
check_disk_space() {
    local required_space=5000000  # 5GB in KB
    local available_space=$(df -k / | awk 'NR==2 {print $4}')
    
    if [ "$available_space" -lt "$required_space" ]; then
        handle_error 1 "Insufficient disk space. Required: 5GB, Available: $((available_space/1024/1024))GB"
    fi
}

# Check disk space before proceeding
check_disk_space

# Function to verify system requirements
check_system_requirements() {
    local min_memory=4096  # 4GB in MB
    local available_memory=$(free -m | awk '/Mem:/ {print $7}')
    
    if [ "$available_memory" -lt "$min_memory" ]; then
        handle_error 1 "Insufficient memory. Required: 4GB, Available: $((available_memory/1024))GB"
    fi
    
    # Check CPU cores
    local min_cores=2
    local cpu_cores=$(nproc)
    
    if [ "$cpu_cores" -lt "$min_cores" ]; then
        handle_error 1 "Insufficient CPU cores. Required: 2, Available: $cpu_cores"
    fi
}

# Check system requirements before proceeding
check_system_requirements
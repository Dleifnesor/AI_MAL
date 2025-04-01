#!/bin/bash
# Installation script for AI_MAL
# This script installs dependencies and sets up the environment

# Exit on any error
set -e

# Function to check if running with sudo
check_sudo() {
    if [ "$EUID" -ne 0 ]; then 
        echo "[-] This script needs to be run with sudo privileges"
        echo "    Please run: sudo ./install.sh"
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
echo "[+] Checking essential system dependencies..."
MISSING_DEPS=()
ESSENTIAL_DEPS=("curl" "git" "python3" "python3-pip" "python3-venv" "gcc" "python3-dev" "libpq-dev" "libffi-dev" "bc")

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
    echo "[-] Could not determine package manager. Please install dependencies manually."
    exit 1
fi

# Install dependencies based on package manager
for dep in "${ESSENTIAL_DEPS[@]}"; do
    if ! command_exists "$dep"; then
        MISSING_DEPS+=("$dep")
    fi
done

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    echo "[!] Installing missing dependencies: ${MISSING_DEPS[*]}"
    eval "$UPDATE_CMD"
    eval "$INSTALL_CMD ${MISSING_DEPS[*]}" || {
        echo "[-] Failed to install dependencies. Please install them manually:"
        echo "    sudo $INSTALL_CMD ${MISSING_DEPS[*]}"
        exit 1
    }
fi

# Check for Python 3
if ! command_exists python3; then
    echo "Python 3 is not installed. Please install Python 3 and try again."
    exit 1
fi

# Check Python version (using python3 -c instead of bc)
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo "[+] Python version $PYTHON_VERSION is compatible"
else
    echo "Python 3.8 or higher is required. Current version: $PYTHON_VERSION"
    exit 1
fi

# Ensure pip is available and up to date
echo "[+] Ensuring pip is available and up to date..."
if ! command_exists pip3; then
    echo "[!] pip3 not found. Installing python3-pip..."
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
        echo "[-] Could not determine package manager. Please install dos2unix manually."
        return 1
    fi
    return 0
}

# Check and install dos2unix
echo "[+] Checking for dos2unix..."
if ! command_exists dos2unix; then
    echo "[!] dos2unix is not installed. Attempting to install..."
    if ! install_dos2unix; then
        echo "[-] Failed to install dos2unix. Will try to fix line endings manually."
    fi
fi

# Fix line endings in all script files
echo "[+] Fixing line endings in script files..."
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
echo "[+] Processing script files..."
while IFS= read -r -d '' file; do
    echo "    Fixing line endings in: $file"
    fix_line_endings "$file"
done < <(find "$INSTALL_DIR" -type f \( -name "*.py" -o -name "*.sh" -o -name "AI_MAL" \) -print0)

# Verify the files are executable and have correct line endings
echo "[+] Verifying file permissions and line endings..."
for file in "$INSTALL_DIR/AI_MAL" "$INSTALL_DIR/adaptive_nmap_scan.py"; do
    if [ -f "$file" ]; then
        # Make executable
        chmod +x "$file"
        # Double-check line endings
        fix_line_endings "$file"
        echo "    Verified: $file"
    else
        echo "[!] Warning: Could not find $file"
    fi
done

# Create a virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv venv || { echo "Failed to create virtual environment"; exit 1; }
fi

# Create the virtual environment activation wrapper script
echo "[+] Creating virtual environment wrapper script..."
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
echo "[+] Activating virtual environment..."
source venv/bin/activate || { echo "Failed to activate virtual environment"; exit 1; }

# Upgrade pip and install required packages in the virtual environment
echo "[+] Installing Python dependencies..."
python3 -m pip install --upgrade pip

# Install required packages in the virtual environment
python3 -m pip install --upgrade requests pymetasploit3 psutil netifaces || { 
    echo "Failed to install Python dependencies"
    exit 1
}

# Check if nmap is installed
echo "[+] Checking for system dependencies..."
if ! command_exists nmap; then
    echo "[!] nmap is not installed. Attempting to install..."
    
    # Check the package manager and install nmap
    if command_exists apt-get; then
        sudo apt-get update
        sudo apt-get install -y nmap
    elif command_exists yum; then
        sudo yum install -y nmap
    elif command_exists dnf; then
        sudo dnf install -y nmap
    elif command_exists pacman; then
        sudo pacman -S --noconfirm nmap
    elif command_exists brew; then
        brew install nmap
    else
        echo "[-] Could not determine package manager. Please install nmap manually."
        exit 1
    fi
fi

# Verify nmap installation
if command_exists nmap; then
    NMAP_VERSION=$(nmap --version | head -n 1)
    echo "[+] Found $NMAP_VERSION"
    echo "[+] AI_MAL will use system nmap via subprocess"
else
    echo "[-] nmap is not installed. Please install it manually."
    exit 1
fi

# Check for Metasploit Framework
echo "[+] Checking for Metasploit Framework..."
if ! command_exists msfconsole; then
    echo "[!] Metasploit Framework not found. Attempting to install..."
    if command_exists apt-get; then
        sudo apt-get update
        sudo apt-get install -y metasploit-framework postgresql
    else
        echo "[!] Metasploit Framework not found. MSF integration will not be available."
        echo "    To install Metasploit Framework, follow instructions at:"
        echo "    https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
    fi
fi

# Set up PostgreSQL for Metasploit with improved error handling
echo "[+] Setting up PostgreSQL for Metasploit..."
setup_postgresql() {
    local max_retries=30
    local retry_count=1
    
    if command_exists psql; then
        # Ensure PostgreSQL is installed and running
        if ! command_exists systemctl || ! systemctl is-active --quiet postgresql; then
            echo "[!] Starting PostgreSQL service..."
            if command_exists systemctl; then
                # First enable the service
                sudo systemctl enable postgresql || {
                    echo "[!] Failed to enable PostgreSQL service"
                    return 1
                }
                
                # Then start the service
                sudo systemctl start postgresql || {
                    echo "[!] Failed to start PostgreSQL with systemctl, trying service command..."
                    sudo service postgresql start
                }
                
                # Verify the service is running
                if ! systemctl is-active --quiet postgresql; then
                    echo "[!] PostgreSQL service is not running after start attempt"
                    return 1
                fi
            else
                sudo service postgresql start
            fi
            
            # Wait for PostgreSQL to start with timeout
            echo "[+] Waiting for PostgreSQL to start..."
            while [ $retry_count -le $max_retries ]; do
                if pg_isready -q; then
                    echo "[+] PostgreSQL is ready"
                    break
                fi
                echo -n "."
                sleep 1
                retry_count=$((retry_count + 1))
            done
            
            if [ $retry_count -gt $max_retries ]; then
                echo "[-] PostgreSQL failed to start within $max_retries seconds"
                # Try to get more information about the failure
                if command_exists systemctl; then
                    echo "[!] PostgreSQL service status:"
                    systemctl status postgresql | cat
                fi
                if [ -f /var/log/postgresql/postgresql-*.log ]; then
                    echo "[!] Last few lines of PostgreSQL log:"
                    tail -n 20 /var/log/postgresql/postgresql-*.log
                fi
                return 1
            fi
        fi
        
        # Initialize Metasploit database with proper error handling
        echo "[+] Initializing Metasploit database..."
        if command_exists msfdb; then
            if ! sudo msfdb init; then
                echo "[!] msfdb init failed, trying alternative setup..."
                
                # Create msf user and database with proper error handling
                if ! sudo -u postgres psql -c "CREATE USER msf WITH PASSWORD 'msf';" 2>/dev/null; then
                    echo "[!] User msf might already exist, continuing..."
                fi
                
                if ! sudo -u postgres psql -c "CREATE DATABASE msf OWNER msf;" 2>/dev/null; then
                    echo "[!] Database msf might already exist, continuing..."
                fi
                
                if ! sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE msf TO msf;" 2>/dev/null; then
                    echo "[!] Failed to grant privileges, continuing..."
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
        echo "[!] PostgreSQL not found. Installing..."
        if command_exists apt-get; then
            sudo apt-get update
            sudo apt-get install -y postgresql postgresql-contrib
            
            # Enable and start PostgreSQL after installation
            if command_exists systemctl; then
                sudo systemctl enable postgresql
                sudo systemctl start postgresql
                
                # Verify the service is running
                if ! systemctl is-active --quiet postgresql; then
                    echo "[!] PostgreSQL service is not running after installation"
                    return 1
                fi
            else
                sudo service postgresql start
            fi
            
            # Retry database initialization with timeout
            echo "[+] Retrying Metasploit database initialization..."
            if command_exists msfdb; then
                if ! sudo msfdb init; then
                    echo "[-] Failed to initialize Metasploit database"
                    return 1
                fi
            fi
        else
            echo "[-] PostgreSQL installation failed. Metasploit will run without database support."
            return 1
        fi
    fi
    return 0
}

# Run PostgreSQL setup
if ! setup_postgresql; then
    echo "[!] Warning: Metasploit database setup completed with errors"
    echo "    Some features may be limited"
fi

# Function to verify Ollama installation
verify_ollama() {
    local max_retries=30
    local retry_count=1
    
    echo "[+] Verifying Ollama installation..."
    while [ $retry_count -le $max_retries ]; do
        if curl -s http://localhost:11434/api/version > /dev/null; then
            echo "[+] Ollama is running and accessible"
            return 0
        fi
        echo -n "."
        sleep 1
        retry_count=$((retry_count + 1))
    done
    
    echo "[-] Ollama failed to start or is not accessible"
    return 1
}

# Function to pull Ollama model with retries
pull_ollama_model() {
    local model=$1
    local max_retries=3
    local retry_count=1
    
    echo "[+] Pulling Ollama model: $model"
    while [ $retry_count -le $max_retries ]; do
        if curl -s -X POST http://localhost:11434/api/pull -d "{\"name\": \"$model\"}" > /dev/null; then
            echo "[+] Successfully pulled model: $model"
            return 0
        fi
        echo "[!] Failed to pull model (attempt $retry_count/$max_retries)"
        retry_count=$((retry_count + 1))
        sleep 5
    done
    
    echo "[-] Failed to pull model after $max_retries attempts"
    return 1
}

# Install and configure Ollama
echo "[+] Installing Ollama..."
install_ollama() {
    local system_type=$(get_system_type)
    local linux_distro=$(get_linux_distro)
    
    case $system_type in
        "linux")
            case $linux_distro in
                "ubuntu"|"debian")
                    curl -fsSL https://ollama.com/install.sh | sudo sh || {
                        echo "[-] Failed to install Ollama using install script"
                        return 1
                    }
                    ;;
                "fedora"|"centos"|"rhel")
                    curl -fsSL https://ollama.com/install.sh | sudo sh || {
                        echo "[-] Failed to install Ollama using install script"
                        return 1
                    }
                    ;;
                *)
                    echo "[-] Unsupported Linux distribution: $linux_distro"
                    return 1
                    ;;
            esac
            
            # Start Ollama service
            if command_exists systemctl; then
                sudo systemctl start ollama || {
                    echo "[-] Failed to start Ollama service"
                    return 1
                }
            else
                sudo service ollama start || {
                    echo "[-] Failed to start Ollama service"
                    return 1
                }
            fi
            ;;
            
        "macos")
            if command_exists brew; then
                brew install ollama || {
                    echo "[-] Failed to install Ollama using Homebrew"
                    return 1
                }
                brew services start ollama || {
                    echo "[-] Failed to start Ollama service"
                    return 1
                }
            else
                echo "[-] Homebrew not found. Please install Homebrew first"
                return 1
            fi
            ;;
            
        "windows")
            echo "[-] Windows installation not supported in this script"
            echo "    Please install Ollama manually from https://ollama.com/download"
            return 1
            ;;
            
        *)
            echo "[-] Unsupported operating system: $system_type"
            return 1
            ;;
    esac
    
    # Wait for Ollama to start and verify installation
    if ! verify_ollama; then
        return 1
    fi
    
    # Configure Ollama to accept external connections
    echo "[+] Configuring Ollama to accept external connections..."
    if [ -f /etc/ollama/config.json ]; then
        sudo sed -i 's/"listen": "127.0.0.1"/"listen": "0.0.0.0"/' /etc/ollama/config.json
        if command_exists systemctl; then
            sudo systemctl restart ollama
        else
            sudo service ollama restart
        fi
    fi
    
    # Pull required models
    local models=("llama2" "mistral" "codellama")
    for model in "${models[@]}"; do
        if ! pull_ollama_model "$model"; then
            echo "[!] Warning: Failed to pull model: $model"
            echo "    Some features may be limited"
        fi
    done
    
    return 0
}

# Run Ollama installation
if ! install_ollama; then
    echo "[!] Warning: Ollama installation completed with errors"
    echo "    Some features may be limited"
fi

# Make the main files executable
echo "[+] Setting executable permissions..."
chmod +x "$INSTALL_DIR/AI_MAL"

# Create a symbolic link to the AI_MAL script in /usr/local/bin if possible
if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
    echo "[+] Creating symlink in /usr/local/bin..."
    ln -sf "$INSTALL_DIR/AI_MAL" /usr/local/bin/AI_MAL
    echo "[+] AI_MAL installed system-wide. You can run it from any directory with 'AI_MAL'"
else
    echo "[!] Could not create symlink in /usr/local/bin (permission denied)"
    echo "    You can run AI_MAL from this directory with './AI_MAL'"
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
    
    echo "[-] Error: $error_message"
    echo "    Exit code: $exit_code"
    
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
    
    echo "[+] Checking network connectivity..."
    while [ $retry_count -le $max_retries ]; do
        if curl -s https://www.google.com > /dev/null; then
            echo "[+] Network connection verified"
            return 0
        fi
        echo "[!] Network connection failed (attempt $retry_count/$max_retries)"
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
#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${YELLOW}>>> AI_MAL Fast Installation Script${NC}"
echo -e "${YELLOW}>>> This script will install the essential components with minimal dependencies${NC}"

# Parse command line arguments
SKIP_MODELS=false
SKIP_LIBSSL=false # Include libssl-dev by default
SKIP_UPDATE=true # Skip system update by default to avoid hanging
SKIP_MSF=false

for arg in "$@"; do
  case $arg in
    --no-models)
      SKIP_MODELS=true
      shift
      ;;
    --skip-libssl)
      SKIP_LIBSSL=true
      shift
      ;;
    --with-update)
      SKIP_UPDATE=false
      shift
      ;;
    --no-msf)
      SKIP_MSF=true
      shift
      ;;
    --help)
      echo "Usage: ./install.sh [OPTIONS]"
      echo "Options:"
      echo "  --no-models      Skip downloading AI models"
      echo "  --skip-libssl    Skip installing libssl-dev (use if installation hangs)"
      echo "  --with-update    Update system packages (may be slow)"
      echo "  --no-msf         Skip Metasploit installation"
      echo "  --help           Show this help message"
      exit 0
      ;;
  esac
done

# Function to reset terminal
reset_terminal() {
    if command -v tput &>/dev/null; then
        tput sgr0  # Reset all attributes
        tput cnorm # Show cursor
        tput cup 0 0 # Move cursor to home position
        echo -e "\r" # Explicit carriage return
    fi
}

# Function to handle errors
handle_error() {
    echo -e "${RED}Error: $1${NC}"
    reset_terminal
    exit 1
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    handle_error "Please run as root (sudo ./install.sh)"
fi

# Function to check if a package is available in the repositories
check_package_availability() {
    local package=$1
    apt-cache search "^$package$" | grep -q "^$package "
    return $?
}

# Function to safely install a package with fallbacks
safe_install_package() {
    local package=$1
    local is_essential=${2:-false}
    
    echo -e "${CYAN}Installing $package...${NC}"
    
    # Check if package is already installed
    if dpkg -s "$package" &>/dev/null; then
        echo -e "${GREEN}>>> $package is already installed${NC}"
        return 0
    fi
    
    # Check if package is available in repositories
    if ! check_package_availability "$package"; then
        echo -e "${YELLOW}>>> Package $package not found in repositories. Checking alternatives...${NC}"
        
        # Try to find alternative package names (common variations)
        case "$package" in
            "libssl-dev")
                alternatives=("libssl1.1-dev" "libssl3-dev" "libssl1.0-dev" "libssl1.0.2-dev")
                ;;
            *)
                alternatives=()
                ;;
        esac
        
        # Try alternatives if available
        for alt in "${alternatives[@]}"; do
            if check_package_availability "$alt"; then
                echo -e "${YELLOW}>>> Found alternative package: $alt${NC}"
                DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$alt" 2>&1 | while read line; do
                    echo -e "${CYAN}>>> $line${NC}"
                done
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}>>> Successfully installed alternative package: $alt${NC}"
                    return 0
                fi
            fi
        done
        
        # If no alternatives found and it's essential, fail
        if [ "$is_essential" = true ]; then
            echo -e "${RED}>>> Essential package $package not available. Installation cannot continue.${NC}"
            return 1
        else
            echo -e "${YELLOW}>>> Package $package and alternatives not available. Skipping...${NC}"
            return 0
        fi
    fi
    
    # Install the package
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$package" 2>&1 | while read line; do
        echo -e "${CYAN}>>> $line${NC}"
    done
    
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}>>> Failed to install $package. Trying with --fix-missing...${NC}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y --fix-missing --no-install-recommends "$package" 2>&1 | while read line; do
            echo -e "${CYAN}>>> $line${NC}"
        done
        
        if [ $? -ne 0 ]; then
            if [ "$is_essential" = true ]; then
                echo -e "${RED}>>> Failed to install essential package $package. Installation cannot continue.${NC}"
                return 1
            else
                echo -e "${YELLOW}>>> Failed to install $package. Continuing anyway...${NC}"
                return 0
            fi
        fi
    fi
    
    echo -e "${GREEN}>>> Successfully installed $package${NC}"
    reset_terminal
    return 0
}

# Function to install libssl-dev with alternatives
install_libssl() {
    echo -e "${CYAN}Installing OpenSSL development libraries...${NC}"
    
    # Check if already installed
    if dpkg -s libssl-dev &>/dev/null; then
        echo -e "${GREEN}>>> libssl-dev is already installed${NC}"
        return 0
    fi
    
    # Try standard installation first
    echo -e "${YELLOW}>>> Attempting standard installation of libssl-dev...${NC}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libssl-dev 2>&1 | while read line; do
        echo -e "${CYAN}>>> $line${NC}"
    done
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}>>> Successfully installed libssl-dev${NC}"
        return 0
    fi
    
    # If standard installation fails, try alternative methods
    echo -e "${YELLOW}>>> Standard installation failed. Trying alternative methods...${NC}"
    
    # Method 1: Try installing from Kali repository
    echo -e "${YELLOW}>>> Attempting installation from Kali repository...${NC}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libssl-dev=3.0.11-1 2>&1 | while read line; do
        echo -e "${CYAN}>>> $line${NC}"
    done
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}>>> Successfully installed libssl-dev from Kali repository${NC}"
        return 0
    fi
    
    # Method 2: Try installing from Debian repository
    echo -e "${YELLOW}>>> Attempting installation from Debian repository...${NC}"
    echo "deb http://deb.debian.org/debian bullseye main" > /etc/apt/sources.list.d/debian.list
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libssl-dev/bullseye 2>&1 | while read line; do
        echo -e "${CYAN}>>> $line${NC}"
    done
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}>>> Successfully installed libssl-dev from Debian repository${NC}"
        # Clean up
        rm /etc/apt/sources.list.d/debian.list
        apt-get update
        return 0
    fi
    
    # Method 3: Try building from source
    echo -e "${YELLOW}>>> Attempting to build from source...${NC}"
    apt-get install -y build-essential wget
    cd /tmp
    wget https://www.openssl.org/source/openssl-3.0.11.tar.gz
    tar xzf openssl-3.0.11.tar.gz
    cd openssl-3.0.11
    ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared
    make
    make install
    echo "/usr/local/ssl/lib" > /etc/ld.so.conf.d/openssl.conf
    ldconfig
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}>>> Successfully built and installed OpenSSL from source${NC}"
        return 0
    fi
    
    # If all methods fail
    echo -e "${RED}>>> Failed to install libssl-dev. Some features may not work properly.${NC}"
    echo -e "${YELLOW}>>> You can try installing it manually or continue without it.${NC}"
    return 1
}

# Function to install python-ldap dependencies
install_python_ldap_deps() {
    echo -e "${CYAN}Installing python-ldap dependencies...${NC}"
    
    # Install required packages
    local packages=(
        "libldap2-dev"
        "libsasl2-dev"
        "libssl-dev"
        "python3-dev"
    )
    
    for package in "${packages[@]}"; do
        safe_install_package "$package" true
    done
    
    # Verify installation
    if ! dpkg -s libldap2-dev &>/dev/null || ! dpkg -s libsasl2-dev &>/dev/null; then
        echo -e "${RED}>>> Failed to install python-ldap dependencies. Installation cannot continue.${NC}"
        return 1
    fi
    
    echo -e "${GREEN}>>> Successfully installed python-ldap dependencies${NC}"
    return 0
}

# Create necessary directories
echo -e "${YELLOW}>>> Creating necessary directories...${NC}"
# More robust directory creation
# Create required directories
echo -e "${YELLOW}>>> Creating required directories...${NC}"
required_dirs=(
    "logs"
    "scan_results"
    "msf_resources"
    "generated_scripts"
    "workspaces"
    "exfiltrated_data"
    "implant_logs"
    "scripts"
)

for dir in "${required_dirs[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        echo -e "${GREEN}>>> Created directory: $dir${NC}"
    else
        echo -e "${GREEN}>>> Directory already exists: $dir${NC}"
    fi
done

# Make sure sources.list is properly configured
echo -e "${YELLOW}>>> Checking package sources...${NC}"
if [ -f /etc/apt/sources.list ]; then
    # Check if main repositories are enabled
    if ! grep -q "^deb.*main" /etc/apt/sources.list; then
        echo -e "${YELLOW}>>> Warning: Main repository not found in sources.list${NC}"
        echo -e "${YELLOW}>>> This might cause package installation issues${NC}"
    fi
    
    # Check for kali-rolling repository (specific to Kali Linux)
    if ! grep -q "kali-rolling" /etc/apt/sources.list && [ -f /etc/os-release ] && grep -q "kali" /etc/os-release; then
        echo -e "${YELLOW}>>> Kali Linux detected but kali-rolling repository not found${NC}"
        echo -e "${YELLOW}>>> Consider adding 'deb http://http.kali.org/kali kali-rolling main contrib non-free'${NC}"
    fi
fi

# Update package repository but skip upgrade
if [ "$SKIP_UPDATE" = false ]; then
    echo -e "${YELLOW}>>> Updating package repository (skipping upgrade)...${NC}"
    apt-get update
fi

# Install system dependencies
echo -e "${YELLOW}>>> Installing system dependencies...${NC}"
packages=(
    "python3"
    "python3-pip"
    "python3-venv"
    "git"
    "curl"
    "wget"
    "build-essential"
    "libffi-dev"
    "libssl-dev"
    "libldap2-dev"
    "libsasl2-dev"
    "python3-dev"
    "nmap"
    "metasploit-framework"
)

for package in "${packages[@]}"; do
    safe_install_package "$package" true
done

# Install python-ldap dependencies before pip install
install_python_ldap_deps

# Install OpenSSL development libraries
if [ "$SKIP_LIBSSL" = false ]; then
    install_libssl
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}>>> libssl-dev installation failed. Some features may not work.${NC}"
        echo -e "${YELLOW}>>> You can try installing it manually or continue without it.${NC}"
        read -p "Continue installation? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
fi

# Additional important libraries that might be needed
additional_libs=(
    "libyaml-dev" "zlib1g-dev" "libffi-dev" "libxml2-dev" "libxslt1-dev"
)

echo -e "${YELLOW}>>> Installing additional important libraries...${NC}"
for lib in "${additional_libs[@]}"; do
    safe_install_package "$lib"
done

# Trap to handle script interruptions
trap_script_interruption() {
    echo -e "\n${RED}>>> Installation interrupted. Cleaning up...${NC}"
    
    # Kill any running processes
    pkill -P $$ 2>/dev/null || true
    
    # Remove temporary directories
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi

    # Clean up package management locks if needed
    if [ -f /var/lib/dpkg/lock-frontend ]; then
        rm -f /var/lib/dpkg/lock-frontend
        rm -f /var/lib/dpkg/lock
        rm -f /var/cache/apt/archives/lock
    fi
    
    echo -e "${YELLOW}>>> Installation was interrupted. Some components may not be installed properly.${NC}"
    exit 1
}

# Set trap for interruptions
trap trap_script_interruption INT TERM

# Global temporary directory
TMP_DIR=$(mktemp -d)

# Install Metasploit Framework only if not skipped
if [ "$SKIP_MSF" = false ]; then
    echo -e "${YELLOW}>>> Installing Metasploit Framework (this may take some time)...${NC}"
    
    # First make sure PostgreSQL is installed
    safe_install_package "postgresql" false
    
    if ! dpkg -s "metasploit-framework" &>/dev/null; then
        # Try repository installation first
        echo -e "${CYAN}Attempting to install metasploit-framework from repositories...${NC}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends metasploit-framework
        
        if [ $? -ne 0 ]; then
            echo -e "${YELLOW}>>> Repository installation failed. Trying alternative installation...${NC}"
            
            # Make sure we have the prerequisites
            prerequisites=("curl" "gnupg2" "ruby" "ruby-dev" "build-essential" "patch")
            for prereq in "${prerequisites[@]}"; do
                safe_install_package "$prereq" false
            done
            
            # Try downloading and installing from Rapid7
            echo -e "${CYAN}Adding Metasploit Framework repository...${NC}"
            curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key | apt-key add -
            echo "deb https://apt.metasploit.com/ kali main" > /etc/apt/sources.list.d/metasploit.list
            apt-get update
            
            DEBIAN_FRONTEND=noninteractive apt-get install -y metasploit-framework
            if [ $? -ne 0 ]; then
                echo -e "${RED}>>> Failed to install Metasploit Framework${NC}"
                echo -e "${YELLOW}>>> Some penetration testing features will not be available${NC}"
            else
                echo -e "${GREEN}>>> Successfully installed Metasploit Framework from Rapid7 repository${NC}"
            fi
        else
            echo -e "${GREEN}>>> Successfully installed Metasploit Framework from repository${NC}"
        fi
    else
        echo -e "${GREEN}>>> Metasploit Framework is already installed${NC}"
    fi
    
    # Initialize Metasploit database
    if dpkg -s "metasploit-framework" &>/dev/null; then
        echo -e "${YELLOW}>>> Configuring Metasploit database...${NC}"
        
        # Ensure PostgreSQL is running
        if ! systemctl is-active --quiet postgresql; then
            echo -e "${YELLOW}>>> Starting PostgreSQL service...${NC}"
            systemctl start postgresql
            systemctl enable postgresql
        fi
        
        # Initialize msfdb
        if command -v msfdb &>/dev/null; then
            echo -e "${CYAN}Initializing Metasploit database...${NC}"
            msfdb init || echo -e "${YELLOW}>>> Warning: msfdb initialization failed. Some features may not work correctly.${NC}"
        fi
    fi
else
    echo -e "${YELLOW}>>> Skipping Metasploit Framework installation (--no-msf flag detected)${NC}"
fi

# Clean up at the end of the script
cleanup() {
    echo -e "${YELLOW}>>> Cleaning up temporary files...${NC}"
    
    # Remove temporary directory
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
    
    # Fix any broken packages
    echo -e "${YELLOW}>>> Fixing any broken packages...${NC}"
    apt-get -f install -y || true
    
    echo -e "${GREEN}>>> Cleanup completed${NC}"
}

# Register cleanup function to run at script exit
trap cleanup EXIT

# Ensure nmap has proper permissions
echo -e "${YELLOW}>>> Setting proper permissions for nmap...${NC}"
if [ -f /usr/bin/nmap ]; then
    chmod +s /usr/bin/nmap
    echo -e "${GREEN}>>> Set setuid bit on nmap to allow privileged operations${NC}"
else
    echo -e "${RED}>>> Could not find nmap executable. Scanning functionality may be limited.${NC}"
fi

# Create Python virtual environment
echo -e "${YELLOW}>>> Creating Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo -e "${YELLOW}>>> Installing Python dependencies...${NC}"
pip install --quiet --upgrade pip wheel setuptools

# Install core Python dependencies individually for reliability
core_packages=(
    "rich" "python-nmap" "pathlib" "requests" "numpy" "pandas" 
    "argparse" "pyyaml" "cryptography" "tqdm" "paramiko" "scapy"
    "colorama" "prompt_toolkit" "beautifulsoup4" "lxml"
)

for package in "${core_packages[@]}"; do
    echo -e "${CYAN}Installing $package...${NC}"
    pip install --quiet $package
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}>>> Warning: Failed to install $package. Trying alternative installation...${NC}"
        pip install --quiet --no-deps $package
        if [ $? -ne 0 ]; then
            echo -e "${YELLOW}>>> Warning: Alternative installation failed. Some functionality may be limited.${NC}"
        fi
    fi
done

# Install package in development mode
echo -e "${YELLOW}>>> Installing AI_MAL package...${NC}"
pip install --quiet -e .

# Create a symbolic link to ensure the module is in Python's path
echo -e "${YELLOW}>>> Creating Python module symlink...${NC}"
SITE_PACKAGES=$(python -c "import site; print(site.getsitepackages()[0])")
if [ -d "$SITE_PACKAGES" ]; then
    # Check if we already have a symlink or the actual package there
    if [ ! -e "$SITE_PACKAGES/AI_MAL" ]; then
        ln -sf "$(pwd)/AI_MAL" "$SITE_PACKAGES/AI_MAL"
        echo -e "${GREEN}>>> Created symlink for AI_MAL module${NC}"
    else
        echo -e "${GREEN}>>> AI_MAL module already in Python path${NC}"
    fi
else
    echo -e "${YELLOW}>>> Warning: Could not find site-packages directory${NC}"
fi

# Install Ollama if not already installed
if ! command -v ollama &> /dev/null; then
    echo -e "${YELLOW}>>> Installing Ollama...${NC}"
    
    # Download the script to a file
    curl -fsSL https://ollama.com/install.sh -o ollama_install.sh
    
    # Make it executable and run
    chmod +x ollama_install.sh
    ./ollama_install.sh
    
    # Clean up
    rm -f ollama_install.sh
    
    # Start Ollama service
    systemctl start ollama || echo -e "${YELLOW}>>> Warning: Failed to start Ollama service. AI analysis may not work.${NC}"
    systemctl enable ollama || echo -e "${YELLOW}>>> Warning: Failed to enable Ollama service.${NC}"
    
    # Wait for Ollama to start
    echo -e "${YELLOW}>>> Waiting for Ollama service to start...${NC}"
    sleep 10
else
    echo -e "${GREEN}>>> Ollama is already installed${NC}"
fi

# Download models if not skipped
if [ "$SKIP_MODELS" = false ]; then
    # Check if Ollama is running
    if ! curl -s -f http://localhost:11434/api/tags &>/dev/null; then
        echo -e "${YELLOW}>>> Warning: Ollama service is not running. Starting it...${NC}"
        systemctl start ollama || echo -e "${YELLOW}>>> Failed to start Ollama service. AI models cannot be downloaded.${NC}"
        sleep 5
    fi
    
    if curl -s -f http://localhost:11434/api/tags &>/dev/null; then
        echo -e "${YELLOW}>>> Downloading AI models (this may take some time)...${NC}"
        
        # Function to safely pull an Ollama model with timeout
        pull_model_with_timeout() {
            model_name=$1
            timeout_seconds=${2:-900}  # Default timeout 15 minutes
            
            echo -e "${YELLOW}>>> Pulling model: ${model_name} (timeout: ${timeout_seconds}s)${NC}"
            
            # Start model pull in background, but track PID
            ollama pull $model_name > /tmp/ollama_pull_${model_name//\//_}.log 2>&1 &
            pull_pid=$!
            
            # Monitor the pull process
            elapsed=0
            check_interval=10
            success=false
            start_time=$(date +%s)
            
            while [ $elapsed -lt $timeout_seconds ]; do
                # Check if process is still running
                if ! kill -0 $pull_pid 2>/dev/null; then
                    # Process completed
                    if grep -q "success" /tmp/ollama_pull_${model_name//\//_}.log; then
                        echo -e "${GREEN}>>> Successfully pulled model: ${model_name}${NC}"
                        success=true
                        break
                    else
                        echo -e "${RED}>>> Model pull process ended but success message not found: ${model_name}${NC}"
                        break
                    fi
                fi
                
                # Calculate elapsed time based on current time
                current_time=$(date +%s)
                elapsed=$((current_time - start_time))
                
                # Display progress (if log contains percentage)
                if [ $((elapsed % 30)) -eq 0 ] || [ $elapsed -eq 0 ]; then
                    if grep -q "%" /tmp/ollama_pull_${model_name//\//_}.log; then
                        progress=$(grep "%" /tmp/ollama_pull_${model_name//\//_}.log | tail -1)
                        echo -e "${CYAN}>>> Progress: ${progress}${NC}"
                    else
                        echo -e "${CYAN}>>> Still downloading ${model_name}... (${elapsed}s elapsed)${NC}"
                    fi
                fi
                
                # Check if model appears in list anyway (sometimes download finishes but process hangs)
                if ollama list 2>/dev/null | grep -q "$model_name"; then
                    echo -e "${GREEN}>>> Model ${model_name} is now available!${NC}"
                    success=true
                    break
                fi
                
                sleep $check_interval
            done
            
            # If we timed out or the process is hanging, kill it
            if [ $elapsed -ge $timeout_seconds ] || (! $success && kill -0 $pull_pid 2>/dev/null); then
                echo -e "${YELLOW}>>> Timeout reached or process hanging for ${model_name}. Terminating...${NC}"
                kill $pull_pid 2>/dev/null || true
                
                # Final check to see if the model is available anyway
                if ollama list 2>/dev/null | grep -q "$model_name"; then
                    echo -e "${GREEN}>>> Despite timeout, model ${model_name} is available!${NC}"
                    success=true
                else
                    echo -e "${RED}>>> Failed to pull model ${model_name} within timeout period.${NC}"
                fi
            fi
            
            # Clean up log
            rm -f /tmp/ollama_pull_${model_name//\//_}.log
            
            # Return success status
            $success
            return $?
        }
        
        # Try to pull primary model first with 15-minute timeout
        if ollama list 2>/dev/null | grep -q "artifish/llama3.2-uncensored"; then
            echo -e "${GREEN}>>> Primary model artifish/llama3.2-uncensored is already available${NC}"
            primary_model_available=true
        else
            echo -e "${YELLOW}>>> Pulling primary AI model: artifish/llama3.2-uncensored...${NC}"
            if pull_model_with_timeout "artifish/llama3.2-uncensored" 900; then
                primary_model_available=true
            else
                primary_model_available=false
                echo -e "${YELLOW}>>> Will continue with fallback model${NC}"
            fi
        fi
        
        # Pull fallback model if primary failed or doesn't exist, with 5-minute timeout (smaller model)
        if ollama list 2>/dev/null | grep -q "gemma:1b"; then
            echo -e "${GREEN}>>> Fallback model gemma:1b is already available${NC}"
            fallback_model_available=true
        else
            echo -e "${YELLOW}>>> Pulling fallback AI model: gemma:1b...${NC}"
            if pull_model_with_timeout "gemma:1b" 300; then
                fallback_model_available=true
            else
                fallback_model_available=false
                echo -e "${YELLOW}>>> Fallback model download failed or timed out${NC}"
            fi
        fi
        
        # Final check - see if we have at least one model
        if ollama list 2>/dev/null | grep -q -E "artifish/llama3.2-uncensored|gemma:1b"; then
            echo -e "${GREEN}>>> At least one AI model is available for use${NC}"
        else
            echo -e "${YELLOW}>>> No AI models are currently available. AI analysis will be limited.${NC}"
            echo -e "${YELLOW}>>> You can manually download models later with: ollama pull artifish/llama3.2-uncensored${NC}"
        fi
    else
        echo -e "${RED}>>> Ollama service is not responding. AI models cannot be downloaded.${NC}"
        echo -e "${YELLOW}>>> You can manually download models later with: ollama pull artifish/llama3.2-uncensored${NC}"
    fi
else
    echo -e "${YELLOW}>>> Skipping AI model download (--no-models flag detected)${NC}"
    echo -e "${YELLOW}>>> You can manually download models later with: ollama pull artifish/llama3.2-uncensored${NC}"
fi

# Function to create AI_MAL executable
create_executable() {
    echo -e "${CYAN}Creating AI_MAL executable...${NC}"
    
    # Create the executable script
    cat > /usr/local/bin/AI_MAL << 'EOF'
#!/bin/bash

# Find the AI_MAL installation directory
if [ -d "/home/kali/AI_MAL" ]; then
    AI_MAL_DIR="/home/kali/AI_MAL"
elif [ -h "$0" ]; then
    # If this script is a symlink, find the original location
    SCRIPT_DIR=$(dirname $(readlink -f "$0"))
    AI_MAL_DIR=$(readlink -f "${SCRIPT_DIR}/../..")
else
    # Try to find it in standard locations
    for dir in "/opt/AI_MAL" "/usr/local/share/AI_MAL" "/usr/share/AI_MAL"; do
        if [ -d "$dir" ]; then
            AI_MAL_DIR="$dir"
            break
        fi
    done
fi

# If we couldn't find it, use the current directory as a fallback
if [ -z "$AI_MAL_DIR" ]; then
    AI_MAL_DIR="$PWD"
    echo "Warning: Could not locate AI_MAL installation directory. Using current directory." >&2
fi

# Change to the AI_MAL directory
cd "$AI_MAL_DIR" || { echo "Error: Failed to change to AI_MAL directory." >&2; exit 1; }

# Activate virtual environment if it exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Run the main module with all arguments
if ! python -m AI_MAL.main.scanner "$@" 2>/dev/null; then
    if ! python3 -m AI_MAL.main.scanner "$@"; then
        echo "Error: Failed to run AI_MAL. Check installation and try again." >&2
        exit 1
    fi
fi
EOF

    # Make the script executable
    chmod +x /usr/local/bin/AI_MAL
    
    # Create a symlink in the current directory
    ln -sf /usr/local/bin/AI_MAL "$(pwd)/AI_MAL"
    
    echo -e "${GREEN}>>> AI_MAL executable created successfully${NC}"
}

# Add this to the main installation section, after package installation
create_executable

# Create a configuration file if it doesn't exist
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}>>> Creating default configuration file...${NC}"
    cat > .env << 'EOF'
OLLAMA_MODEL=artifish/llama3.2-uncensored
OLLAMA_FALLBACK_MODEL=gemma:1b
OLLAMA_URL=http://localhost:11434
LOG_DIR=logs
WORKSPACE_DIR=workspaces
EOF
    echo -e "${GREEN}>>> Created default configuration file${NC}"
fi

# Verify installation
echo -e "${YELLOW}>>> Verifying installation...${NC}"

# Check if Python virtual environment is properly installed
if [ -d "venv" ] && [ -f "venv/bin/activate" ]; then
    echo -e "${GREEN}>>> Python virtual environment is properly installed${NC}"
    
    # Verify critical Python packages
    source venv/bin/activate
    
    critical_pkgs=("rich" "nmap" "requests")
    missing_pkgs=()
    
    for pkg in "${critical_pkgs[@]}"; do
        python -c "import $pkg" 2>/dev/null
        if [ $? -ne 0 ]; then
            missing_pkgs+=("$pkg")
        fi
    done
    
    if [ ${#missing_pkgs[@]} -gt 0 ]; then
        echo -e "${YELLOW}>>> Warning: Some critical Python packages are missing: ${missing_pkgs[*]}${NC}"
        echo -e "${YELLOW}>>> Trying to reinstall them...${NC}"
        
        for pkg in "${missing_pkgs[@]}"; do
            pip install --no-cache-dir $pkg
        done
    else
        echo -e "${GREEN}>>> All critical Python packages are installed${NC}"
    fi
else
    echo -e "${RED}>>> Python virtual environment is missing or incomplete${NC}"
    echo -e "${YELLOW}>>> You may need to run: python3 -m venv venv${NC}"
fi

# Check nmap
if command -v nmap &> /dev/null; then
    echo -e "${GREEN}>>> nmap is installed${NC}"
    # Test nmap basic functionality
    if nmap -V &>/dev/null; then
        echo -e "${GREEN}>>> nmap is functioning correctly${NC}"
    else
        echo -e "${RED}>>> nmap is installed but not functioning correctly${NC}"
    fi
else
    echo -e "${RED}>>> nmap is not installed. Scanning functionality will not work.${NC}"
fi

# Check if AI_MAL executable is available
if [ -f "/usr/local/bin/AI_MAL" ] && [ -x "/usr/local/bin/AI_MAL" ]; then
    echo -e "${GREEN}>>> AI_MAL executable is available and has proper permissions${NC}"
else
    echo -e "${RED}>>> AI_MAL executable is missing or not executable${NC}"
fi

# Final summary
echo ""
echo -e "${GREEN}╔═════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           AI_MAL Installation Complete          ║${NC}"
echo -e "${GREEN}╚═════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}>>> You can now run AI_MAL with: AI_MAL <target> [options]${NC}"
echo -e "${GREEN}>>> Example: AI_MAL 192.168.1.1 --vuln --os --services${NC}"
echo -e "${GREEN}>>> For a local test, try: AI_MAL 127.0.0.1 --vuln --os${NC}"
echo ""

# Reset terminal to fix any formatting issues
reset_terminal
exit 0 
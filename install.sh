#!/bin/bash
# Installation script for AI_MAL
# This script installs dependencies and sets up the environment

# Exit on any error
set -e

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

# Check for essential system dependencies
echo "[+] Checking essential system dependencies..."
MISSING_DEPS=()
ESSENTIAL_DEPS=("curl" "git" "python3" "python3-pip" "python3-venv" "gcc" "python3-dev" "libpq-dev" "libffi-dev")

for dep in "${ESSENTIAL_DEPS[@]}"; do
    if ! dpkg -l | grep -q "^ii  $dep"; then
        MISSING_DEPS+=("$dep")
    fi
done

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    echo "[!] Installing missing dependencies: ${MISSING_DEPS[*]}"
    sudo apt-get update
    sudo apt-get install -y "${MISSING_DEPS[@]}" || {
        echo "[-] Failed to install dependencies. Please install them manually:"
        echo "    sudo apt-get install ${MISSING_DEPS[*]}"
        exit 1
    }
fi

# Check for Python 3
if ! command_exists python3; then
    echo "Python 3 is not installed. Please install Python 3 and try again."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if (( $(echo "$PYTHON_VERSION < 3.8" | bc -l) )); then
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

# Update pip to latest version
python3 -m pip install --upgrade pip

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

# Upgrade pip and install required packages
echo "[+] Installing Python dependencies..."
python3 -m pip install --upgrade pip

# Install required packages directly
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

# Set up PostgreSQL for Metasploit
echo "[+] Setting up PostgreSQL for Metasploit..."
if command_exists psql; then
    # Ensure PostgreSQL is installed and running
    if ! command_exists systemctl || ! systemctl is-active --quiet postgresql; then
        echo "[!] Starting PostgreSQL service..."
        if command_exists systemctl; then
            sudo systemctl start postgresql || {
                echo "[!] Failed to start PostgreSQL with systemctl, trying service command..."
                sudo service postgresql start
            }
        else
            sudo service postgresql start
        fi
        
        # Wait for PostgreSQL to start
        echo "[+] Waiting for PostgreSQL to start..."
        for i in {1..30}; do
            if pg_isready -q; then
                break
            fi
            sleep 1
        done
    fi
    
    # Initialize Metasploit database
    echo "[+] Initializing Metasploit database..."
    if command_exists msfdb; then
        sudo msfdb init || {
            echo "[!] msfdb init failed, trying alternative setup..."
            # Create msf user and database if they don't exist
            sudo -u postgres psql -c "CREATE USER msf WITH PASSWORD 'msf';" 2>/dev/null || true
            sudo -u postgres psql -c "CREATE DATABASE msf OWNER msf;" 2>/dev/null || true
            sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE msf TO msf;" 2>/dev/null || true
            
            # Create database.yml if it doesn't exist
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
        }
    fi
else
    echo "[!] PostgreSQL not found. Installing..."
    if command_exists apt-get; then
        sudo apt-get update
        sudo apt-get install -y postgresql postgresql-contrib
        
        # Try to start PostgreSQL after installation
        if command_exists systemctl; then
            sudo systemctl start postgresql
        else
            sudo service postgresql start
        fi
        
        # Retry database initialization
        echo "[+] Retrying Metasploit database initialization..."
        if command_exists msfdb; then
            sudo msfdb init
        fi
    else
        echo "[!] PostgreSQL installation failed. Metasploit will run without database support."
    fi
fi

# Check Ollama installation and setup
echo "[+] Setting up Ollama..."
if ! command_exists ollama; then
    echo "[!] Ollama not found. Installing..."
    
    # Check system type and install Ollama
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux installation
        curl -fsSL https://ollama.com/install.sh | sh
        
        # Wait for Ollama installation to complete
        echo "[+] Waiting for Ollama installation to complete..."
        sleep 5
        
        # Start Ollama service
        if command_exists systemctl; then
            sudo systemctl enable ollama
            sudo systemctl start ollama
        else
            # Start Ollama in the background
            nohup ollama serve > /dev/null 2>&1 &
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS installation
        if command_exists brew; then
            brew install ollama
        else
            echo "[!] Homebrew not found. Installing Ollama manually..."
            curl -fsSL https://ollama.com/install.sh | sh
        fi
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        # Windows installation instructions
        echo "[!] Windows detected. Please install Ollama manually:"
        echo "   1. Visit https://ollama.com/download"
        echo "   2. Download and run the Windows installer"
        echo "   3. After installation, run 'ollama serve' in a new terminal"
        echo "   4. Wait for the service to start, then continue this installation"
        read -p "Press Enter once Ollama is installed and running..."
    else
        echo "[-] Unsupported operating system. Please install Ollama manually from https://ollama.com/download"
        exit 1
    fi
fi

# Configure Ollama to listen on all interfaces
echo "[+] Configuring Ollama to accept external connections..."
if command_exists systemctl && systemctl list-unit-files | grep -q "ollama.service"; then
    # Create systemd override directory if it doesn't exist
    sudo mkdir -p /etc/systemd/system/ollama.service.d/
    
    # Create or update the override.conf file
    cat << 'EOF' | sudo tee /etc/systemd/system/ollama.service.d/override.conf > /dev/null
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
Environment="OLLAMA_ORIGINS=*"
EOF
    
    # Reload systemd and restart Ollama
    echo "[+] Reloading systemd configuration and restarting Ollama..."
    sudo systemctl daemon-reload
    sudo systemctl restart ollama
    
    # Wait for Ollama to start up
    echo "[+] Waiting for Ollama to start..."
    for i in {1..30}; do
        if curl -s "http://localhost:11434/api/tags" > /dev/null; then
            echo "[+] Ollama API is now accessible"
            break
        fi
        echo -n "."
        sleep 1
    done
    echo
else
    echo "[!] Ollama service not found, configuring environment variables..."
    # Try system-wide profile first, fall back to user profile
    if [ -w "/etc/profile.d" ]; then
        PROFILE_FILE="/etc/profile.d/ollama.sh"
        echo '# Ollama configuration' | sudo tee "$PROFILE_FILE" > /dev/null
        echo 'export OLLAMA_HOST=0.0.0.0:11434' | sudo tee -a "$PROFILE_FILE" > /dev/null
        echo 'export OLLAMA_ORIGINS=*' | sudo tee -a "$PROFILE_FILE" > /dev/null
    else
        PROFILE_FILE="$HOME/.profile"
        echo '# Ollama configuration' >> "$PROFILE_FILE"
        echo 'export OLLAMA_HOST=0.0.0.0:11434' >> "$PROFILE_FILE"
        echo 'export OLLAMA_ORIGINS=*' >> "$PROFILE_FILE"
    fi
    
    # Export variables for current session
    export OLLAMA_HOST=0.0.0.0:11434
    export OLLAMA_ORIGINS=*
    
    # Restart Ollama if it's running
    if pgrep ollama > /dev/null; then
        echo "[+] Restarting Ollama with new configuration..."
        pkill ollama
        sleep 2
        nohup ollama serve > /dev/null 2>&1 &
        
        # Wait for Ollama to start
        echo "[+] Waiting for Ollama to start..."
        for i in {1..30}; do
            if curl -s "http://localhost:11434/api/tags" > /dev/null; then
                echo "[+] Ollama API is now accessible"
                break
            fi
            echo -n "."
            sleep 1
        done
        echo
    fi
fi

# Check if Ollama API is accessible and pull models
echo "[+] Checking Ollama API and pulling models..."
if curl -s "http://localhost:11434/api/tags" > /dev/null; then
    echo "[+] Ollama API is accessible. Pulling required models..."
    
    # Function to pull model with progress indicator
    pull_model() {
        local model=$1
        local desc=$2
        echo "[+] Pulling $model model ($desc)..."
        echo "    This may take some time depending on your internet connection..."
        if ollama pull "$model" > /dev/null 2>&1; then
            echo "[+] Successfully pulled $model"
            return 0
        else
            echo "[!] Failed to pull $model. Will try again with progress output..."
            if ollama pull "$model"; then
                echo "[+] Successfully pulled $model on second attempt"
                return 0
            else
                echo "[!] Failed to pull $model. You'll need to pull it manually with: ollama pull $model"
                return 1
            fi
        fi
    }
    
    # Pull models with retries
    pull_model "qwen2.5-coder:7b" "primary model, recommended for better results"
    pull_model "gemma3:1b" "backup model for systems with limited resources"
    
    # Verify models were installed
    echo "[+] Verifying installed models..."
    ollama list
else
    echo "[!] Could not connect to Ollama API at http://localhost:11434"
    echo "    Please check if Ollama is running with: ollama serve"
    echo "    After starting Ollama, pull the required models manually:"
    echo "      ollama pull qwen2.5-coder:7b"
    echo "      ollama pull gemma3:1b"
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
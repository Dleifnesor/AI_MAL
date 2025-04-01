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

# Check and install dos2unix
if ! command_exists dos2unix; then
    echo "[!] dos2unix is not installed. Attempting to install..."
    
    # Check the package manager and install dos2unix
    if command_exists apt-get; then
        sudo apt-get update
        sudo apt-get install -y dos2unix
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
    fi
fi

# Fix line endings in all script files
echo "[+] Fixing line endings in script files..."
if command_exists dos2unix; then
    find "$INSTALL_DIR" -type f -name "*.py" -o -name "*.sh" -o -name "AI_MAL" | while read -r file; do
        dos2unix "$file"
    done
else
    echo "[!] dos2unix not found, attempting to fix line endings manually..."
    find "$INSTALL_DIR" -type f -name "*.py" -o -name "*.sh" -o -name "AI_MAL" | while read -r file; do
        sed -i 's/\r$//' "$file"
    done
fi

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
if command_exists msfconsole; then
    echo "[+] Metasploit Framework found"
    
    # Check if PostgreSQL is installed for Metasploit
    if command_exists psql; then
        echo "[+] PostgreSQL found for Metasploit database"
        
        # Check if PostgreSQL is running
        if command_exists systemctl && systemctl is-active --quiet postgresql; then
            echo "[+] PostgreSQL service is running"
        else
            echo "[!] Starting PostgreSQL service..."
            if command_exists systemctl; then
                sudo systemctl start postgresql || echo "[!] Failed to start PostgreSQL. You may need to start it manually."
            fi
        fi
        
        # Initialize Metasploit database if needed
        echo "[+] Initializing Metasploit database..."
        if command_exists msfdb; then
            sudo msfdb init || echo "[!] Failed to initialize Metasploit database. You may need to initialize it manually."
        fi
    else
        echo "[!] PostgreSQL not found. Metasploit will run without database support."
    fi
else
    echo "[!] Metasploit Framework not found. MSF integration will not be available."
    echo "    To install Metasploit Framework, follow instructions at:"
    echo "    https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
fi

# Check Ollama installation
echo "[+] Checking for Ollama..."
if ! command_exists ollama; then
    echo "[!] Ollama not found. Installing..."
    
    # Check system type and install Ollama
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux installation
        curl -fsSL https://ollama.com/install.sh | sh
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
        echo "   Visit https://ollama.com/download and download the Windows installer"
        echo "   Ollama must be running before using AI_MAL"
    else
        echo "[-] Unsupported operating system. Please install Ollama manually from https://ollama.com/download"
    fi
else
    echo "[+] Ollama already installed"
fi

# Configure Ollama to listen on all interfaces
echo "[+] Configuring Ollama to accept external connections..."
if command_exists systemctl && systemctl list-unit-files | grep -q "ollama.service"; then
    # Create systemd override directory if it doesn't exist
    sudo mkdir -p /etc/systemd/system/ollama.service.d/
    
    # Create or update the override.conf file
    cat << EOF | sudo tee /etc/systemd/system/ollama.service.d/override.conf > /dev/null
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
    sleep 5
else
    echo "[!] Ollama service not found, adding environment variables to system profile..."
    # Add environment variables to system-wide profile
    PROFILE_FILE="/etc/profile.d/ollama.sh"
    cat << EOF | sudo tee "$PROFILE_FILE" > /dev/null 2>&1 || {
        # If system-wide profile fails, try user profile
        PROFILE_FILE="$HOME/.profile"
        cat << INNER_EOF >> "$PROFILE_FILE"
# Ollama configuration
export OLLAMA_HOST=0.0.0.0:11434
export OLLAMA_ORIGINS=*
INNER_EOF
    }
    
    # Source the profile
    echo "[+] Added Ollama environment variables to profile"
    echo "[!] You may need to restart your shell or run: source $PROFILE_FILE"
    
    # Try to restart Ollama if it's running
    if pgrep ollama > /dev/null; then
        echo "[+] Stopping and restarting Ollama..."
        pkill ollama
        sleep 2
        nohup ollama serve > /dev/null 2>&1 &
        echo "[+] Waiting for Ollama to start..."
        sleep 5
    fi
fi

# Check if Ollama API is accessible and pull models
echo "[+] Checking Ollama API and pulling models..."
if curl -s "http://localhost:11434/api/tags" > /dev/null; then
    echo "[+] Ollama API is accessible. Pulling required models..."
    
    # Pull primary model: qwen2.5-coder:7b (recommended for better results)
    echo "[+] Pulling qwen2.5-coder:7b model (primary model)..."
    echo "    This may take some time depending on your internet connection..."
    ollama pull qwen2.5-coder:7b || echo "[!] Failed to pull qwen2.5-coder:7b model. You'll need to pull it manually."
    
    # Pull backup model: gemma3:1b (for low-resource compatibility)
    echo "[+] Pulling gemma3:1b model (for systems with limited resources)..."
    echo "    This is a smaller model for systems with limited RAM..."
    ollama pull gemma3:1b || echo "[!] Failed to pull gemma3:1b model. You'll need to pull it manually."
    
    # Verify models were installed
    if ollama list | grep -q "qwen2.5-coder:7b"; then
        echo "[+] Successfully installed qwen2.5-coder:7b model"
    else
        echo "[!] Warning: qwen2.5-coder:7b model may not have installed correctly"
    fi
    
    if ollama list | grep -q "gemma3:1b"; then
        echo "[+] Successfully installed gemma3:1b model"
    else
        echo "[!] Warning: gemma3:1b model may not have installed correctly"
    fi
else
    echo "[!] Could not connect to Ollama API at http://localhost:11434"
    echo "    Make sure Ollama is running before using AI_MAL"
    echo "    You'll need to pull the models manually with:"
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
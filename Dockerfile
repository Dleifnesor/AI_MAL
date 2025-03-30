FROM kalilinux/kali-rolling

# Set non-interactive mode for apt
ENV DEBIAN_FRONTEND=noninteractive

# Update and install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        nmap \
        metasploit-framework \
        postgresql \
        curl \
        sudo \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

# Create and set working directory
WORKDIR /opt/ai_mal

# Copy AI_MAL files
COPY . /opt/ai_mal/

# Install Python dependencies
RUN pip3 install --no-cache-dir python-nmap requests pymetasploit3 netifaces ipaddress

# Setup Metasploit
RUN service postgresql start && \
    msfdb init

# Install Ollama
RUN curl -fsSL https://ollama.com/install.sh | sh

# Make scripts executable
RUN chmod +x AI_MAL adaptive_nmap_scan.py install.sh

# Create symbolic link for system-wide access
RUN ln -sf /opt/ai_mal/AI_MAL /usr/local/bin/AI_MAL

# Create directory for generated scripts
RUN mkdir -p /opt/ai_mal/generated_scripts
VOLUME /opt/ai_mal/generated_scripts

# Custom entrypoint to handle services and arguments
RUN echo '#!/bin/bash\n\
service postgresql start\n\
# Start msfrpcd in the background\n\
msfrpcd -P "msf_password" -S -a 127.0.0.1 -p 55553 &\n\
# Start Ollama in the background\n\
ollama serve &\n\
# Wait for services to be ready\n\
sleep 5\n\
# Check for and pull models if not present\n\
echo "Checking Ollama models..."\n\
if ! ollama list | grep -q "llama3"; then\n\
  echo "Pulling llama3..."\n\
  ollama pull llama3\n\
else\n\
  echo "llama3 model already installed"\n\
fi\n\
if ! ollama list | grep -q "qwen2.5-coder:7b"; then\n\
  echo "Pulling qwen2.5-coder:7b..."\n\
  ollama pull qwen2.5-coder:7b\n\
else\n\
  echo "qwen2.5-coder:7b model already installed"\n\
fi\n\
# Execute AI_MAL with provided arguments\n\
exec /opt/ai_mal/AI_MAL "$@"\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

# Default to displaying help
CMD ["--help"] 
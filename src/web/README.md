# AI_MAL Web Interface

This is the web interface component for the AI_MAL penetration testing platform. It provides a user-friendly GUI that integrates with OpenVAS, Metasploit, and AI capabilities.

## Features

- **Dashboard**: View statistics and system status at a glance
- **Scan Management**: Create, configure, and monitor scans
- **Vulnerability Visualization**: View and filter discovered vulnerabilities
- **Real-time Updates**: Track scan progress with live updates
- **AI Analysis**: Get AI-powered insights and recommendations
- **OpenVAS Integration**: Seamless integration with OpenVAS vulnerability scanner
- **Metasploit Integration**: Exploit discovery and management
- **Custom Scripts**: Generate and manage custom penetration testing scripts

## Running the Web Interface

You can run the web interface in several ways:

### From the installer

If you installed AI_MAL using the installer script, you can run the web interface using:

```bash
ai-mal-web
```

### From the AI_MAL command

```bash
AI_MAL --web-interface [--web-host HOST] [--web-port PORT] [--debug]
```

### Directly from source

```bash
cd /path/to/AI_MAL
source venv/bin/activate
python src/web/run.py
```

## Configuration

The web interface uses the following default configuration:

- **Host**: 0.0.0.0 (accessible from any IP)
- **Port**: 8443
- **Login Credentials**: Same as your OpenVAS credentials (admin/password)

## Requirements

- Flask
- Flask-SocketIO
- Eventlet
- Werkzeug

These packages are automatically installed when running the web interface.

## Security Considerations

- The web interface runs with the same privileges as the AI_MAL tool
- Access should be restricted to trusted networks
- Consider using a reverse proxy with HTTPS for production environments
- Default credentials should be changed after installation 
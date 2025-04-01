#!/usr/bin/env python3
"""
Mock data for AI_MAL tests
"""

# Mock scan results
MOCK_SCAN_RESULTS = {
    "scan_info": {
        "scan_start": "2024-03-20T10:00:00",
        "scan_end": "2024-03-20T10:01:00",
        "scan_type": "stealth",
        "target": "127.0.0.1"
    },
    "hosts": [
        {
            "ip": "127.0.0.1",
            "hostname": "localhost",
            "status": "up",
            "ports": [
                {
                    "port": 22,
                    "state": "open",
                    "service": "ssh",
                    "version": "OpenSSH 8.2p1",
                    "scripts": [
                        {
                            "name": "ssh-auth-methods",
                            "output": "Supported authentication methods: publickey,password"
                        }
                    ]
                },
                {
                    "port": 80,
                    "state": "open",
                    "service": "http",
                    "version": "Apache 2.4.41",
                    "scripts": [
                        {
                            "name": "http-server-header",
                            "output": "Apache/2.4.41 (Ubuntu)"
                        }
                    ]
                },
                {
                    "port": 443,
                    "state": "open",
                    "service": "https",
                    "version": "Apache 2.4.41",
                    "scripts": [
                        {
                            "name": "ssl-cert",
                            "output": "Subject: CN=localhost"
                        }
                    ]
                }
            ],
            "os": {
                "name": "Linux",
                "family": "Linux",
                "generation": "4.15",
                "type": "general purpose",
                "vendor": "Ubuntu",
                "accuracy": 100
            }
        }
    ]
}

# Mock AI analysis results
MOCK_AI_ANALYSIS = {
    "risk_level": "MEDIUM",
    "summary": "Target system has multiple open ports with potential security concerns",
    "vulnerabilities": [
        {
            "name": "Weak SSH Configuration",
            "severity": "MEDIUM",
            "description": "SSH service allows password authentication",
            "port": 22,
            "service": "ssh"
        },
        {
            "name": "Outdated Apache Version",
            "severity": "HIGH",
            "description": "Apache 2.4.41 has known vulnerabilities",
            "port": 80,
            "service": "http"
        }
    ],
    "attack_vectors": [
        "SSH password brute force",
        "Apache vulnerability exploitation",
        "SSL/TLS attacks"
    ],
    "recommendations": [
        "Disable password authentication for SSH",
        "Update Apache to latest version",
        "Configure strong SSL/TLS settings"
    ]
}

# Mock Metasploit exploits
MOCK_EXPLOITS = [
    {
        "name": "exploit/unix/ssh/sshexec",
        "description": "SSH User Code Execution",
        "rank": "excellent",
        "disclosure_date": "2012-01-01",
        "references": [
            "CVE-2012-0001"
        ]
    },
    {
        "name": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
        "description": "Apache mod_cgi Bash Environment Variable Code Injection",
        "rank": "excellent",
        "disclosure_date": "2014-09-24",
        "references": [
            "CVE-2014-6271"
        ]
    }
]

# Mock script generation results
MOCK_SCRIPTS = {
    "port_scanner.py": """
#!/usr/bin/env python3
import nmap

def scan_ports(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sS -sV')
    return nm.all_hosts()
""",
    "service_enum.py": """
#!/usr/bin/env python3
import socket

def enumerate_services(target, ports):
    services = {}
    for port in ports:
        try:
            service = socket.getservbyport(port)
            services[port] = service
        except:
            services[port] = "unknown"
    return services
""",
    "vuln_scanner.py": """
#!/usr/bin/env python3
import requests

def scan_vulnerabilities(target):
    vulnerabilities = []
    # Add vulnerability scanning logic here
    return vulnerabilities
"""
}

# Mock execution results
MOCK_EXECUTION_RESULTS = [
    {
        "script": "port_scanner.py",
        "status": "success",
        "output": "Found 3 open ports",
        "output_file": "port_scan_results.txt"
    },
    {
        "script": "service_enum.py",
        "status": "success",
        "output": "Enumerated 3 services",
        "output_file": "service_enum_results.txt"
    },
    {
        "script": "vuln_scanner.py",
        "status": "success",
        "output": "Found 2 vulnerabilities",
        "output_file": "vuln_scan_results.txt"
    }
] 
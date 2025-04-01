from setuptools import setup, find_packages

setup(
    name="ai_mal",
    version="0.1.0",
    packages=find_packages(include=['ai_mal', 'ai_mal.*']),
    install_requires=[
        "aiohttp>=3.8.0",
        "python-dotenv>=0.19.0",
        "typing-extensions>=4.0.0",
        "requests>=2.31.0",
        "colorama>=0.4.6",
        "rich>=13.7.0",
        "pyyaml>=6.0.1",
        "jinja2>=3.1.3",
        "python-nmap>=0.7.1",
        # Additional dependencies for data exfiltration
        "paramiko>=2.7.2",  # For SSH connections
        "smbclient>=1.0.0",  # For SMB connections
    ],
    entry_points={
        "console_scripts": [
            "AI_MAL=main:main",
        ],
    },
    author="Dleifnesor",
    author_email="phlegmenthusiast@gmail.com",
    description="AI-Powered Penetration Testing Tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/ai-mal/ai_mal",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    include_package_data=True,
    package_data={
        'ai_mal': ['core/*', 'examples/*', 'tests/*'],
    },
) 
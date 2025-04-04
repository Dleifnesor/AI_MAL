from setuptools import setup, find_packages

setup(
    name="AI_MAL",
    version="0.1.0",
    packages=find_packages(),
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
        "paramiko>=2.7.2",  # For SSH connections
        "scapy>=2.4.5",
        "cryptography>=3.4.7",
        "numpy>=1.21.2",
        "pandas>=1.3.3",
        "scikit-learn>=0.24.2",
        "torch>=1.9.0",
        "transformers>=4.11.3",
        "tqdm>=4.62.3",
        "click>=8.0.1",
    ],
    entry_points={
        "console_scripts": [
            "AI_MAL=AI_MAL.main:main",
        ],
    },
    author="Dleifnesor",
    author_email="phlegmenthusiast@gmail.com",
    description="AI-Powered Penetration Testing Tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Dleifnesor/AI_MAL",
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
        'AI_MAL': ['core/*', 'examples/*', 'tests/*'],
    },
) 
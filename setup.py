from setuptools import setup, find_packages
import os

# Get the long description from the README file
with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

# Get the requirements from requirements.txt
with open('requirements.txt') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="AI_MAL",
    version="0.1.0",
    packages=find_packages(),
    package_dir={'': '.'},
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'ai_mal=AI_MAL.main:main',
            'ai_mal_openvas=AI_MAL.openvas_scan:main',
        ],
    },
    author="Dleifnesor",
    author_email="phlegmenthusiast@gmail.com",
    description="AI-Powered Penetration Testing Tool",
    long_description=long_description,
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
    package_data={
        'AI_MAL': [
            '*.py',
            'core/*.py',
            'main/*.py',
            '*.md',
            '*.txt',
            '*.sh'
        ],
    },
    data_files=[
        ('/usr/local/bin', ['AI_MAL']),
        ('/etc/AI_MAL', ['.env']),
    ],
    scripts=['install.sh'],
) 
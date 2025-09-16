#!/usr/bin/env python
"""Setup script for AIWAF Flask package."""

from setuptools import setup, find_packages
import os

# Read the contents of README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="aiwaf-flask",
    version="0.2.0-beta",
    author="Aayush Gauba",
    author_email="gauba.aayush@gmail.com",
    description="Advanced AI-powered Web Application Firewall for Flask with intelligent threat detection, rate limiting, IP blocking, and real-time protection against web attacks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/aayushgauba/aiwaf_flask",
    project_urls={
        "Bug Tracker": "https://github.com/aayushgauba/aiwaf_flask/issues",
        "Documentation": "https://github.com/aayushgauba/aiwaf_flask#readme",
        "Source Code": "https://github.com/aayushgauba/aiwaf_flask",
    },
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Framework :: Flask",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        "flask>=2.0.0",
        "flask-sqlalchemy>=3.0.0",
    ],
    extras_require={
        "ai": [
            "numpy>=1.20.0",
            "scikit-learn>=1.0.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "flask-testing>=0.8.1",
            "pytest-cov>=4.0.0",
        ],
        "all": [
            "numpy>=1.20.0",
            "scikit-learn>=1.0.0",
            "pytest>=7.0.0",
            "flask-testing>=0.8.1",
            "pytest-cov>=4.0.0",
        ],
    },
    keywords=[
        "flask", "security", "firewall", "web", "protection", "middleware", 
        "rate-limiting", "ip-blocking", "ddos", "waf"
    ],
    entry_points={
        'console_scripts': [
            'aiwaf-console=aiwaf_flask.cli:main',
            'aiwaf=aiwaf_flask.cli:main',
            'aiwaf-train=train_aiwaf:main',
        ],
    },
    package_data={
        'aiwaf_flask': ['resources/*', 'resources/*.pkl', 'resources/*.json'],
    },
    include_package_data=True,
    zip_safe=False,
)
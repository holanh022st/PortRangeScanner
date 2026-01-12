"""
Setup script for Enterprise Port Scanner application.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="enterprise-port-scanner",
    version="1.0.0",
    author="Port Scanner Team",
    author_email="security@example.com",
    description="Enterprise-grade port scanner with PyQt6 GUI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/holanh022st/PortRangeScanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "port-scanner=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["resources/*.qss", "resources/presets/*.json"],
    },
)

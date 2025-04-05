#!/usr/bin/env python3
"""
Setup script for ACO-based Secure IoT Routing App
"""
from setuptools import setup, find_packages

setup(
    name="aco_secure_iot_routing",
    version="1.0.0",
    description="Ant Colony Optimization based Secure IoT Routing Application",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        "pymongo>=3.11.0",
        "networkx>=2.5",
        "numpy>=1.19.0",
        "matplotlib>=3.3.0",
        "pandas>=1.1.0",
        "python-dateutil>=2.8.1",
        "pillow>=8.0.0",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "aco-secure-iot=main:main"
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
)

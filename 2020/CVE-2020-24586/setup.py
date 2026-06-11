from setuptools import setup, find_packages

setup(
    name             = "fracture",
    version          = "1.0.0",
    description      = "FragAttacks WiFi penetration framework",
    long_description = open("README.md").read(),
    long_description_content_type = "text/markdown",
    author           = "Alec",
    url              = "https://github.com/fracture-wifi/fracture",
    license          = "MIT",
    packages         = find_packages(),
    python_requires  = ">=3.10",
    install_requires = [
        "scapy>=2.5.0",
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "flask>=2.3.0",
    ],
    entry_points = {
        "console_scripts": [
            "fracture=fracture.__main__:main",
        ],
    },
    classifiers = [
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)

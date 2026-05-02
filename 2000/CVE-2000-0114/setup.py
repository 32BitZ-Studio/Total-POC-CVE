from setuptools import setup

VERSION = '0.0.1'
DESCRIPTION = 'A Tool to find an Easy Bounty - CVE-2000-0114'
LONG_DESCRIPTION = 'This is a tool used by several security researchers to find CVE-2000-0114.'

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="CVE-2000-0114",
    version=VERSION,
    author="@karthithehacker",
    author_email="<contact@karthithehacker.com>",
    long_description=long_description,
    long_description_content_type="text/markdown",
    entry_points={
        'console_scripts': [
            'CVE-2000-0114 = cve20000114.main:main',
        ],
    },
    install_requires=['urllib3', 'requests', 'click'],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)

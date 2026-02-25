from setuptools import setup, find_packages

setup(
    name='exploit by trhacknon',
    version='1.0',
    packages=find_packages(),
    install_requires=[
        'requests',
        'pyfiglet',
        'colorama',
        'questionary',
        'cowsay',
    ],
)
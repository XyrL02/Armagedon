from setuptools import setup, find_packages

setup(
    name="armagedon",
    version="1.0.0",
    packages=find_packages(include=["armagedon", "armagedon.*"]),
    install_requires=["impacket", "rich"],
    entry_points={
        "console_scripts": [
            "armagedon=armagedon.__main__:main",
        ],
    },
)

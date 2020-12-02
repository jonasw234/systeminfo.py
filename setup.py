import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="systeminfo.py",
    version="1.0.0",
    author="Jonas A. Wendorf",
    description="Generates systeminfo-like output from offline images",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jonasw234/systeminfo.py",
    packages=setuptools.find_packages(),
    install_requires=["docopt", "regipy"],
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: Linux",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": ["systeminfo=systeminfo.systeminfo:main"],
    },
)

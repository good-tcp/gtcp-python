from setuptools import setup
from pathlib import Path

VERSION = '0.3.0'
DESCRIPTION = 'Simple and secure TCP framework'
THIS_DIRECTORY = Path(__file__).parent
LONG_DESCRIPTION = (THIS_DIRECTORY / "README.md").read_text()

setup(
    name="gtcp", 
    version=VERSION,
    author="Keizou Wang",
    author_email="keizouw8@gmail.com",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    packages=["gtcp"],
    install_requires='pycryptodome',
    keywords=['python', 'tcp', 'crypto', 'sockets'],
    classifiers= [
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: Apache Software License"
    ]
)
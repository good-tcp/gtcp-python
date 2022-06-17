from setuptools import setup, find_packages

VERSION = '0.0.1' 
DESCRIPTION = 'Simple and secure TCP framework'
LONG_DESCRIPTION = 'Simple TCP framework with secure event based messaging'

setup(
    name="gtcp", 
    version=VERSION,
    author="Keizou Wang",
    author_email="keizouw8@gmail.com",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    packages=find_packages(),
    install_requires=[],
    keywords=['python', 'tcp', 'crypto', 'sockets'],
    classifiers= [
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: Apache Software License"
    ]
)
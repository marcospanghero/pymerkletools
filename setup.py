import os

from setuptools import find_packages
from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))
install_requires = [
    "pysha3>=1.0b1; python_version<\"3.6\""
]

setup(
    name='secmerkletools',
    version='1.0.1',
    description='secure HMAC Merkle Tools',
    classifiers=[
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.6",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    url='https://github.com/marcospanghero/pymerkletools',
    author='Marco Spanghero',
    keywords='hmac, merkle tree, blockchain, marcospanghero',
    license="MIT",
    packages=find_packages(exclude=["tests"]),
    include_package_data=False,
    zip_safe=False,
    install_requires=install_requires
)

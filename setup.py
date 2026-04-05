from setuptools import setup, find_packages


with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name="routerxpl",
    version="3.4.8",
    description="Exploitation Framework for Embedded Devices",
    long_description=long_description,
    author="Threat9",
    author_email="marcin@threat9.com",
    url="https://www.threat9.com",
    download_url="https://github.com/threat9/routerxpl/",
    packages=find_packages(),
    include_package_data=True,
    scripts=('rxf.py',),
    entry_points={},
    python_requires='>=3.8',
    install_requires=[
        "requests>=2.32.4",
        "paramiko",
        "pysnmp",
        "pycryptodome",
        "setuptools",
        "telnetlib3; python_version >= '3.13'",
    ],
    extras_require={
        "tests": [
            "pytest",
            "pytest-forked",
            "pytest-xdist",
            "flake8",
        ],
        # Optional: heavyweight; enables CUDA logits in AutoPwn ml_use_gpu when PyTorch sees CUDA.
        "ml-gpu": [
            "torch>=2.0.0",
        ],
    },
    classifiers=[
        "Operating System :: POSIX",
        "Environment :: Console",
        "Environment :: Console :: Curses",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: Utilities",
    ],
)

from setuptools import setup, find_packages

setup(
    name="websec-scanner",
    version="1.0.0",
    author="Kone Bienvenu",
    author_email="kbienvenu263@gmail.com",
    description="Automated Web Scanner: Audits websites for secure headers and CORS flaws.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/konebienvenu/Automated-Web-Scanner",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "rich>=13.0.0",
        "urllib3>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "websec-scanner=scanner.cli:main",
        ],
    },
)

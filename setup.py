from setuptools import setup, find_packages

setup(
    name="cortexsec",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "typer[all]",
        "rich",
        "openai",
        "anthropic",
        "google-generativeai",
        "pydantic",
        "python-dotenv",
        "requests",
        "pyyaml",
        "fpdf2",
        "cryptography"
    ],
    entry_points={
        "console_scripts": [
            "cortexsec=ai_pentest.cli.main:app",
        ],
    },
)

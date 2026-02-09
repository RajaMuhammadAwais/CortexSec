from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop

ASCII_BANNER = r"""
   ______            __            _____
  / ____/___  ____  / /____  _  __/ ___/___  _____
 / /   / __ \/ __ \/ __/ _ \| |/_/\__ \/ _ \/ ___/
/ /___/ /_/ / / / / /_/  __/>  < ___/ /  __/ /
\____/\____/_/ /_/\__/\___/_/|_|/____/\___/_/
"""


def _print_banner():
    print("\n" + ASCII_BANNER)
    print("✅ CortexSec installation hook completed. Use: cortexsec --help\n")


class InstallWithBanner(install):
    def run(self):
        super().run()
        _print_banner()


class DevelopWithBanner(develop):
    def run(self):
        super().run()
        _print_banner()


setup(
    name="cortexsec",
    version="0.3.0",
    packages=find_packages(),
    install_requires=[
        "typer[all]",
        "rich",
        "openai",
        "anthropic",
        "google-genai",
        "pydantic",
        "python-dotenv",
        "requests",
        "pyyaml",
        "fpdf2",
        "cryptography"
    ],
    entry_points={
        "console_scripts": [
            "cortexsec=cortexsec.cli.main:app",
        ],
    },
    cmdclass={
        "install": InstallWithBanner,
        "develop": DevelopWithBanner,
    },
)

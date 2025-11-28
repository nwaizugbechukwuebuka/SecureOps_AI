from __future__ import annotations

from pathlib import Path
from setuptools import find_packages, setup

HERE = Path(__file__).resolve().parent


def _read_requirements(path: Path) -> list[str]:
    if not path.exists():
        return []
    lines = [ln.strip() for ln in path.read_text(encoding="utf8").splitlines()]
    reqs = [ln for ln in lines if ln and not ln.startswith("#")]
    return reqs


long_description = ""
readme = HERE / "README.md"
if readme.exists():
    long_description = readme.read_text(encoding="utf8")

requirements = _read_requirements(HERE / "requirements.txt")

setup(
    name="secureops-ai",
    version="0.1.0",
    description="SecureOps_AI — deterministic local AI-assisted security pipelines",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Chukwuebuka Nwaizugbe",
    url="https://github.com/nwaizugbechukwuebuka/SecureOps_AI",
    license="MIT",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    include_package_data=True,
    install_requires=requirements,
    python_requires=">=3.10",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Framework :: FastAPI",
    ],
    entry_points={
        "console_scripts": [
            "secureops-ai=main:main",
        ]
    },
)

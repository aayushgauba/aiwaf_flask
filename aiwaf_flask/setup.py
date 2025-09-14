from setuptools import setup, find_packages

setup(
    name="aiwaf_flask",
    version="0.1.0",
    description="Flask integration for AIWAF",
    author="Aayush Gauba",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        'flask': ['flask'],
    },
    include_package_data=True,
)

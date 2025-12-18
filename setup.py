from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="icici",
    version="1.0.0",
    description="ICICI IMPS Name Inquiry API Integration for Frappe/ERPNext",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(),
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        "frappe",
        "requests>=2.28.0",
        "cryptography>=41.0.0",
    ],
)


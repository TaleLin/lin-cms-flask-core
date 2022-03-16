"""
Flask-Lin
------------------
"""
import io

import setuptools

with io.open("README.md", "rt", encoding="utf8") as f:
    long_description = f.read()

setuptools.setup(
    name="Lin-CMS",
    version="0.4.8",
    url="https://pypi.org/project/Lin-CMS/",
    license="MIT",
    author="pedroGao",
    author_email="1312342604@qq.com",
    maintainer="sunlin92",
    maintainer_email="sun.melodies@gmail.com",
    description="A simple and practical CMS implememted by flask",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords=["flask", "CMS", "authority", "jwt", "openapi"],
    packages=setuptools.find_packages("src"),
    package_dir={"": "src"},
    zip_safe=False,
    platforms="any",
    install_requires=[
        "Flask==2.0.3",
        "Flask_JWT_Extended==4.3.1",
        "Flask_SQLAlchemy==2.5.1",
        "WTForms==3.0.1",
        "tablib==3.2.0",
        "spectree==0.7.6",
    ],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.8",
    ],
)

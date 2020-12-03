"""
Flask-Lin
------------------
"""
import io

import setuptools

with io.open("README.md", "rt", encoding="utf8") as f:
    long_description = f.read()

setuptools.setup(
    name='Lin-CMS',
    version="0.3.0a3",
    url='https://pypi.org/project/Lin-CMS/',
    license='MIT',
    author='pedroGao',
    author_email='1312342604@qq.com',
    maintainer='pedroGao',
    maintainer_email='1312342604@qq.com',
    description='A simple and practical CMS implememted by flask',
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords=['flask', 'CMS', 'authority', 'jwt'],
    packages=setuptools.find_packages("src"),
    package_dir={"": "src"},
    zip_safe=False,
    platforms='any',
    install_requires=[
        'WTForms==2.3.3',
        'Flask==1.1.2',
        'Flask_JWT_Extended==3.25.0',
        'SQLAlchemy==1.3.20',
        'Flask_SQLAlchemy==2.4.4',
        'tablib==2.0.0'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.6'
    ]
)

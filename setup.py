from setuptools import setup, find_packages

setup(
    name='cle',
    description='CLE Loads Everything (at least, many binary formats!) and provides a pythonic interface to analyze what they are and what they would look like in memory.',
    version='9.1.gitrolling',
    python_requires='>=3.6',
    packages=find_packages(),
    install_requires=[
        'pyelftools>=0.27',
        'cffi',
        'pyvex==9.1.gitrolling',
        'pefile',
        'sortedcontainers>=2.0',
    ],
    extras_require={
        "minidump": ["minidump>=0.0.10"],
        "xbe": ["pyxbe==0.0.2"],
        "ar": ["arpy==1.1.1"],
    }
)

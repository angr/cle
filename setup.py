try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name='cle',
    description='CLE Loads Everything (at least, may binary formats!) and provides a Pythonic interface to analyze what they are and what they would look like in memory.',
    version='4.6.6.28',
    packages=['cle', 'cle.backends', 'cle.relocations'],
    install_requires=[ "pyelftools", "cffi", "idalink", "archinfo", "pyvex", "pefile" ]
)

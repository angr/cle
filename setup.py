try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    import os
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

setup(
    name='cle',
    description='CLE Loads Everything (at least, may binary formats!) and provides a Pythonic interface to analyze what they are and what they would look like in memory.',
    version='6.7.1.13',
    packages=packages,
    install_requires=[ "pyelftools", "cffi", "idalink", "archinfo", "pyvex", "pefile" ]
)

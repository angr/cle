from distutils.core import setup

setup(
    name='cle',
    description='CLE Loads Everything (at least, may binary formats!) and provides a Pythonic interface to analyze what they are and what they would look like in memory.',
    version='1.00',
    packages=['cle'],
    install_requires=[ "pyelftools", "pefile", "cffi", "idalink", "archinfo" ]
)

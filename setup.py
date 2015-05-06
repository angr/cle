from distutils.core import setup

setup(
    name='cle',
    version='1.00',
    packages=['cle'],
    install_requires=[i.strip() for i in open('requirements.txt').readlines() if 'git' not in i]
)

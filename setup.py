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
    description='CLE Loads Everything (at least, many binary formats!) and provides a pythonic interface to analyze what they are and what they would look like in memory.',
    version='7.8.9.26',
    python_requires='<3.0',
    packages=packages,
    install_requires=[
        'pyelftools==0.25',
        'cffi==1.7.0',
        'idalink==0.10',
        'archinfo==7.8.9.26',
        'pyvex==7.8.9.26',
        'pefile==2016.3.28',
    ]
)

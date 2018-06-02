from setuptools import setup, find_packages

setup(
    name='semux',
    version='0.0.1',
    packages=find_packages(),
    install_requires=[
      'PyNaCl==1.2.1',
      'pyblake2==1.1.2',
    ]
)

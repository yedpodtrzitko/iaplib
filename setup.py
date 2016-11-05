from os.path import join, dirname
from setuptools import setup, find_packages

with open(join(dirname(__file__), 'requirements.txt')) as f:
    requirements = [x.strip() for x in f.readlines()]

setup(
    name='IAP Library',
    version='0.1',
    description='Library for IAP verification',
    author='yedpodtrzitko',
    author_email='yedpodtrzitko@gmail.com',
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
)

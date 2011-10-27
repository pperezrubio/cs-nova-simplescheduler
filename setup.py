import os
import sys
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "cloudscaling.nova.scheduler.simple",
    version = "0.1rc1",
    author = "Joe Gordon",
    author_email = "jogo@cloudscaling.com",
    description = ("Cloudscaling's Simple Scheduler without memory oversubscription"),
    license = "Apache 2.0",
    keywords = "Nova scheduler",
    url = "TODO",
    packages = find_packages(),
    zip_safe=False,
    install_requires=['nova'],
    long_description=read('README.md'),
    classifiers=[
        "Environment :: Plugins",
        "License :: OSI Approved :: Apache Software License",
        ],
)

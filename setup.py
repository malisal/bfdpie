import os
import distutils

from setuptools import setup, Extension, Command
from distutils.command import build as build_module
from distutils.command.install import install

BINUTILS_VERSION = "binutils-2.26"

module = Extension(
   name = "bfdpie._bfdpie",
   sources = ["bfdpie.c"],

   # Include dir is our own binutils
   include_dirs= ["tmp/install/include/"],

   # Link against what?
   library_dirs=["tmp/install/lib/"],
   libraries=["bfd", "opcodes", "iberty", "z"],
)
 
class BuildCommand(distutils.command.build.build):
   def run(self):
      # Download and compile binutils first
      os.system("./bfdpie_build.sh %s" % (BINUTILS_VERSION))

      build_module.build.run(self)

setup(
   name = "bfdpie",
   version = "0.1.14",
   description = "A tiny interface around a subset of libBFD. Code based on https://github.com/Groundworkstech/pybfd",
   author = "Luka Malisa",
   author_email = "luka.malisha@gmail.com",
   url = "https://github.com/malisal/bfdpie",
   keywords = ["binary", "libbfd"],
   platforms=["any"],
   classifiers=[
      "Development Status :: 3 - Alpha",

      "Intended Audience :: Developers",
      "License :: OSI Approved :: MIT License",

      "Programming Language :: Python :: 2",
      "Programming Language :: Python :: 3",
   ],

	packages=["bfdpie"],
	package_dir={"bfdpie": "bfdpie"},
   ext_modules = [module],

   test_suite = "tests",

   install_requires = [
      "wheel>=0.29.0",
   ],

   package_data = {
      "bfdpie" : ["bin/dummy.elf"],
   },

   cmdclass={
      "build": BuildCommand,
   }
)


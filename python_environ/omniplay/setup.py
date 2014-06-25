from distutils.core import setup, Extension
import os

try:
    testdir = '/'.join([os.environ['OMNIPLAY_DIR'], "test"])
except KeyError:
    testdir = ''

parseklog = Extension('parseklog',
                include_dirs = [testdir],
                libraries = ['util'],
                library_dirs = [testdir],
                sources = ['parseklogmodule.c'])

setup (name = "Parseklog",
    version = '1.0',
    description = "Extension to parseklib, to parse replay kernel logs from python",
    ext_modules = [parseklog])


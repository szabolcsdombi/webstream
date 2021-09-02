from setuptools import Extension, setup

ext = Extension(
    name='webstream',
    sources=['./webstream.cpp'],
)

setup(
    name='webstream',
    version='0.4.0',
    ext_modules=[ext],
)

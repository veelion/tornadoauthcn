from distutils.core import setup

from tornadoauthcn import __version__, __author__, __license__
setup(
    name = "tornadoauthcn",
    version = __version__,
    author = __author__,
    license = __license__,
    packages = ['tornadoauthcn'],
)

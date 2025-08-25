import toml

from importlib.metadata import version

__appabbr__ = "spits"

try:
    with open("pyproject.toml", mode="r") as config:
        toml_file = toml.load(config)
    __version__ = toml_file["project"]["version"]
    __startmode__ = "dev"
except (Exception, ):
    __startmode__ = "systemd"
    __version__ = version(__appabbr__)

__appname__ = __appabbr__ + " " + __version__


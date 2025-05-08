import toml
from importlib.metadata import version

try:
    with open("pyproject.toml", mode="r") as config:
        toml_file = toml.load(config)
    __version__ = toml_file["project"]["version"]
    __appname__ = "spits" + __version__.split(".")[0]
    __appabbr__ = "spits" + __version__.split(".")[0]
    __startmode__ = "dev"
except (Exception, ):
    __startmode__ = "systemd"
    __appname__ = "spits"
    __appabbr__ = "spits"
    __version__ = version(__appname__)
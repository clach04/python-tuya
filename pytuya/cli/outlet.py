import click
import yaml
from pytuya.cli import cli_root, get_device_from_config, config
from pytuya.devices import OutletDevice


@cli_root.group("outlet")
def outlet():
    pass


@outlet.command()
@click.argument('name', default=None)
def on(name):
    """ sends turn on action to device specified via NAME """
    dev_props = get_device_from_config(config, name)
    dev = OutletDevice(dev_props["id"], dev_props["ip"], dev_props["key"])
    dev.turn_on()


@outlet.command()
@click.argument('name', default=None)
def off(name):
    """ sends turn off action to device specified via NAME """
    dev_props = get_device_from_config(config, name)
    dev = OutletDevice(dev_props["id"], dev_props["ip"], dev_props["key"])
    dev.turn_off()


@outlet.command()
@click.argument('name', default=None)
def state(name):
    """ sends turn off action to device specified via NAME """
    dev_props = get_device_from_config(config, name)
    dev = OutletDevice(dev_props["id"], dev_props["ip"], dev_props["key"])
    print(yaml.dump({name: dev.status()}, default_flow_style=False))


if __name__ == "__main__":
    import sys
    sys.argv = list(sys.argv) + ["outlet", "state", "study"]
    from pytuya import cli_root
    cli_root()

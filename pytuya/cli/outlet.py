import click
import json
from pytuya.cli import cli_root, get_device_from_config, config
from pytuya.devices import OutletDevice


@cli_root.group("outlet")
def outlet():
    pass


@outlet.command()
@click.argument('name', default=None)
@click.argument('switch', default=1)
def on(name, switch):
    """ sends turn on action to device specified via NAME """
    dev_props = get_device_from_config(config, name)
    dev = OutletDevice(dev_props["id"], dev_props["ip"], dev_props["key"])
    dev.turn_on(switch=switch)


@outlet.command()
@click.argument('name', default=None)
@click.argument('switch', default=1, type=click.types.IntRange(0, 3))
def off(name, switch):
    """ sends turn off action to device specified via NAME """
    dev_props = get_device_from_config(config, name)
    dev = OutletDevice(dev_props["id"], dev_props["ip"], dev_props["key"])
    dev.turn_off(switch=switch)


def get_json_state(dev_props):
    return OutletDevice(dev_props["id"], dev_props["ip"], dev_props["key"]).status()


@outlet.command()
@click.argument('name', default=None)
def state(name):
    """ prints the current state of device specified via NAME """
    dev_props = get_device_from_config(config, name)
    print(json.dumps(get_json_state(dev_props)))


if __name__ == "__main__":
    import sys
    # sys.argv = list(sys.argv) + ["outlet", "off", "garden lights", "2"]
    sys.argv = list(sys.argv) + ["outlet", "state", "garden lights"]
    from pytuya.cli import cli_root
    cli_root()

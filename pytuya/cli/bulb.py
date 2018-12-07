import json
import click
from pytuya.cli import cli_root, get_device_from_config, config
from pytuya.devices import BulbDevice


@cli_root.group("bulb")
def bulb():
    pass


@bulb.command()
@click.argument('name', default=None)
def on(name):
    """ sends turn on action to device """
    dev_props = get_device_from_config(config, name)
    dev = BulbDevice(dev_props["id"], dev_props["ip"], dev_props["key"])
    dev.turn_on()


@bulb.command()
@click.argument('name', default=None)
def off(name):
    """ sends turn off action to device """
    dev_props = get_device_from_config(config, name)
    dev = BulbDevice(dev_props["id"], dev_props["ip"], dev_props["key"])
    dev.turn_off()


@bulb.command()
@click.argument('name', default=None)
@click.argument('brightness', default=255, type=click.types.IntRange(min=25, max=255, clamp=True))
@click.option('-t', '--colour_temp', default=None, type=click.types.IntRange(min=25, max=255, clamp=True),
              help="colour temperature")
def brightness(name, brightness, colour_temp):
    """ set brightness of device"""
    dev_props = get_device_from_config(config, name)
    dev = BulbDevice(dev_props["id"], dev_props["ip"], dev_props["key"])
    if colour_temp is None:
        dev.set_brightness(brightness)
    else:
        dev.set_white(brightness=brightness, colour_temp=colour_temp)


@bulb.command()
@click.argument('name', default=None)
@click.argument('r', default=255, type=click.types.IntRange(min=0, max=255, clamp=True))
@click.argument('g', default=255, type=click.types.IntRange(min=0, max=255, clamp=True))
@click.argument('b', default=255, type=click.types.IntRange(min=0, max=255, clamp=True))
def colour(name, r, g, b):
    """ set colour of device using provided R, G, B (red green and blue)"""
    dev_props = get_device_from_config(config, name)
    dev = BulbDevice(dev_props["id"], dev_props["ip"], dev_props["key"])
    dev.set_colour(r, g, b)


def get_json_state(dev_props):
    return BulbDevice(dev_props["id"], dev_props["ip"], dev_props["key"]).status()


@bulb.command()
@click.argument('name', default=None)
def state(name):
    """ prints the current state of device specified via NAME """
    dev_props = get_device_from_config(config, name)
    print(json.dumps(get_json_state(dev_props)))


if __name__ == "__main__":
    import sys
    sys.argv = list(sys.argv) + ["bulb", "state", "garden lights"]
    from pytuya.cli import cli_root
    cli_root()

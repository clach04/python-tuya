import logging
import click
import yaml
from pytuya.devices import CoverDevice
from pytuya.cli.main import cli_root, config, get_device_from_config


@cli_root.group("cover")
def cover():
    pass


def exec_cover_action(name, action_name):
    actions = dict(close=CoverDevice.action_close, open=CoverDevice.action_open,
                   stop=CoverDevice.action_stop)
    dev_props = get_device_from_config(config, name)
    logging.info("sending %s to device %s at %s" % (action_name, name, dev_props["ip"]))
    dev = CoverDevice(dev_props["id"], dev_props["ip"], dev_props["key"])
    dev.send_action(action=actions.get(action_name))


def add_cover_command(action_name):
    cmd = cover.command(action_name)(
        click.argument('name', default=None)(
            lambda name: exec_cover_action(name, action_name)))
    return cmd


for action in "open", "close", "stop":
    add_cover_command(action)


@cover.command()
@click.argument('name', default=None)
def state(name):
    """ sends turn off action to device specified via NAME """
    dev_props = get_device_from_config(config, name)
    dev = CoverDevice(dev_props["id"], dev_props["ip"], dev_props["key"])
    print(yaml.dump({name: dev.state()}, default_flow_style=False))


if __name__ == "__main__":
    import sys

    name = "study blinds"
    sys.argv = list(sys.argv) + ["cover", "state", name.lower()]

    print("\nexecuting test: " + " ".join(sys.argv[1:]))

    cli_root()

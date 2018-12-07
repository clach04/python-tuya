import logging
import click
import json
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


def get_json_state(dev_props):
    return CoverDevice(dev_props["id"], dev_props["ip"], dev_props["key"]).status()


def get_status_descr(status):
    if type(status) is bytes:
        return str(status)
    return {'1': "open", '2': "closed", '3': "stopped"}.get(status.get('dps').get('1'))


@cover.command()
@click.argument('name', default=None)
def state(name):
    """ sends turn off action to device specified via NAME """
    dev_props = get_device_from_config(config, name)
    state = get_json_state(dev_props)
    state["descr"] = get_status_descr(state)
    print(json.dumps(state))


if __name__ == "__main__":
    import sys

    name = "study_blinds"
    sys.argv = list(sys.argv) + ["cover", "state", name.lower()]

    print("\nexecuting test: " + " ".join(sys.argv[1:]))

    cli_root()

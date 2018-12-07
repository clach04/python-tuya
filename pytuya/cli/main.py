import logging
import click
import yaml
import os


def_config_path = os.path.join(os.path.expanduser("~"), ".pytuya.yaml")


class Config(dict):
    _path = None

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        self._path = value
        if os.path.isfile(value):
            with open(self._path, "r") as f:
                content = yaml.load(f.read())

                if content is None:
                    raise RuntimeError("Invalid Config: %s " % self.path)

                super().update(content)

    def __str__(self):
        return yaml.dump(dict(**self), default_flow_style=False)

    def update(self, new_config, **kwargs):
        if os.path.isfile(self._path):
            try:
                old_config = dict(**self)
            except Exception as e:
                logging.warning("%s: generating new config" % e)
                old_config = {}
        else:
            old_config = {}

        old_config.update(new_config)
        with open(self.path, "w") as f:
            config_yaml = yaml.dump(old_config, default_flow_style=False)
            f.write(config_yaml)

        super().update(new_config)

        logging.warning("wrote config at %s with content:\n%s" % (self._path, config_yaml))


config = Config()


def get_keys_from_file(api_response_path):
    # extracts a local key from recorded api responses stored in a file
    from pytuya.utils import KeyExtractor

    with open(api_response_path, "rb") as f:
        api_response = f.read()

    return KeyExtractor.parse_device_keys_from_api_response(api_response)


def build_config(api_response_path):
    from pytuya.utils import query_devices
    keys = get_keys_from_file(api_response_path)
    logging.info("Querying devices")
    devices = query_devices()
    res = {}
    for dev_id, props in keys.items():
        if dev_id not in devices or "ip" not in devices[dev_id]:
            logging.warning("device %s with id %s not found" % (props["name"], dev_id))
            continue
        res[props["name"]] = dict(key=props["key"], ip=devices[dev_id]["ip"], id=dev_id)
    return res


def get_device_from_config(config, name):
    dev_props = config.get(name)
    if dev_props is None:
        name_map = lambda name: name.lower().replace(" ", "").replace("_", "")
        dev_props = {name_map(k): v for k, v in config.items()}.get(name_map(name))
    if dev_props is None:
        raise RuntimeError("Device %s not found in config:\n%s" % (name, config))
    return dev_props


@click.group()
@click.option('-l', '--debug/--no-debug', default=False)
@click.option("-c", "--config_path", default=def_config_path, type=click.Path(file_okay=True, dir_okay=False))
def cli_root(debug, config_path):
    log_level = logging.DEBUG if debug else logging.INFO
    logging.getLogger().setLevel(log_level)
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    config.path = config_path


@cli_root.command("update_config")
@click.argument('api_response_path', default=None, type=click.Path(file_okay=True, dir_okay=False, readable=True))
def update_config(api_response_path):
    # updates a config file using info extracted from api response and queried devices
    new_config = build_config(api_response_path)
    config.update(new_config)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        cli_root()

    test_extract = list(sys.argv) + ["extract", "../../example_response.json"]
    test_query = list(sys.argv) + ["query"]
    test_update_config = list(sys.argv) + ["update_config", "../../example_response.json"]

    test = test_update_config
    print("\nexecuting test: pytuya %s\n" % test)
    sys.argv = test

    cli_root()

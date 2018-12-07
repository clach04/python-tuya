from pytuya.cli.main import cli_root, config, get_device_from_config
from pytuya.cli import bulb, cover, outlet, utils


def main():
    cli_root()


if __name__ == "__main__":
    import sys, os
    sys.argv = list(sys.argv) + ["update_config", os.getcwd()+"/../example_response.json"]
    main()
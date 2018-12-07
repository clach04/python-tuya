import yaml
import click
from pytuya.cli.main import cli_root, get_keys_from_file, build_config, config
from pytuya.utils import query_devices


@cli_root.group("utils")
def utils():
    pass


@utils.command("extract_keys")
@click.argument('api_response_path', default=None, type=click.Path(file_okay=True, dir_okay=False, readable=True))
def extract_keys(api_response_path):
    """ Extracts local keys from a recorded api response. API_RESPONSE_PATH is a file containing the response """
    result = get_keys_from_file(api_response_path)
    pretty = yaml.dump({el["name"]: {k: v for k, v in el.items() if k != "name"} for el in result.values()},
                       default_flow_style=False)
    print(pretty)


@utils.command()
@click.option('-t', '--timeout', default=3.1, help="time spent for listening for device broadcasts")
def discover(timeout):
    """ discovers tuya devices available on the network """
    result = query_devices(timeout_in_s=timeout)
    pretty = yaml.dump(result, default_flow_style=False)
    print(pretty)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        cli_root()

    test_extract = list(sys.argv) + ["utils", "extract_keys", "../../example_response.json"]
    test_query = list(sys.argv) + ["utils", "discover"]

    for test in (test_extract, test_query):
        print("\nexecuting test: pytuya %s\n" % test)
        sys.argv = test
        try:
            cli_root()
        except SystemExit:
            pass

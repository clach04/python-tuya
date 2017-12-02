# Python module to interface with Shenzhen Xenon ESP8266MOD WiFi smart devices
# E.g. https://wikidevi.com/wiki/Xenon_SM-PW701U
#   SKYROKU SM-PW701U Wi-Fi Plug Smart Plug
#   Wuudi SM-S0301-US - WIFI Smart Power Socket Multi Plug with 4 AC Outlets and 4 USB Charging Works with Alexa
#
# This would not exist without the protocol reverse engineering from
# https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
#
# Currently Python 2.x only


import json
import socket


def bin2hex(x, pretty=False):
    if pretty:
        return ''.join('%02X ' % ord(y) for y in x)
    else:
        return ''.join('%02X' % ord(y) for y in x)

def hex2bin(x):
    return ''.join(chr(int(x[y:y+2], 16)) for y in range(0, len(x), 2))


payload_dict = {
  "outlet": {
    "status": {
      "prefix": "000055aa000000000000000a00000046",
      "command": {"gwId": "", "devId": ""},
      "suffix": "000000000000aa55"
    },
    "on": {
      "prefix": "000055aa00000000000000070000009b",
      "command": {"devId": "", "dps": {"1": True}, "uid": "", "t": ""},
      "suffix": "000000000000aa55"
    },
    "off": {
      "prefix": "000055aa0000000000000007000000b3",
      "command": {"devId": "", "dps": {"1": False}, "uid": "", "t": ""},
      "suffix": "000000000000aa55"
    }
  }
}

def generate_payload(device_type, device_id):
    if 'gwId' in payload_dict[device_type]['status']['command']:
        payload_dict[device_type]['status']['command']['gwId'] = device_id;
    if 'devId' in payload_dict[device_type]['status']['command']:
        payload_dict[device_type]['status']['command']['devId'] = device_id;

    # Create byte buffer from hex data
    json_payload = json.dumps(payload_dict[device_type]['status']['command'])
    json_payload = json_payload.replace(' ', '')  # if spaces are not removed device does not respond!
    buffer = payload_dict[device_type]['status']['prefix'] + bin2hex(json_payload) + payload_dict[device_type]['status']['suffix']
    buffer = hex2bin(buffer)
    return buffer


class XenonDevice(object):
    def __init__(self, dev_id, address, local_key=None, dev_type=None):
        """
        dev_id is the "devId" in payload sent to Tuya servers during device activation/registration
        address is network address, e.g. "ip" packet in payload sent to Tuya servers during device activation/registration
        local_key is the "localkey" from payload sent to Tuya servers during device activation/registration
        """
        self.id = dev_id
        self.address = address
        self.local_key = local_key
        self.dev_type = dev_type

        self.port = 6668  # default  and do not expect caller to pass in

    def generate_payload(self, command):
        if 'gwId' in payload_dict[self.dev_type][command]['command']:
            payload_dict[self.dev_type][command]['command']['gwId'] = self.id;
        if 'devId' in payload_dict[self.dev_type][command]['command']:
            payload_dict[self.dev_type][command]['command']['devId'] = self.id;

        # Create byte buffer from hex data
        json_payload = json.dumps(payload_dict[self.dev_type][command]['command'])
        json_payload = json_payload.replace(' ', '')  # if spaces are not removed device does not respond!
        buffer = payload_dict[self.dev_type][command]['prefix'] + bin2hex(json_payload) + payload_dict[self.dev_type][command]['suffix']
        buffer = hex2bin(buffer)
        return buffer


class OutletDevice(XenonDevice):
    def __init__(self, dev_id, address, local_key=None, dev_type=None):
        dev_type = dev_type or 'outlet'
        super(OutletDevice, self).__init__(dev_id, address, local_key, dev_type)

    def status(self):
        # open device, send request, then close connection
        payload = self.generate_payload('status')

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.address, self.port))
        s.send(payload)
        data = s.recv(1024)
        s.close()

        result = data[20:-8]  # hard coded offsets
        #result = data[data.find('{'):data.rfind('}')+1]  # naive marker search, hope neither { nor } occur in header/footer
        result = json.loads(result)
        return result

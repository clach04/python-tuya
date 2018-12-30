# Python module to interface with Shenzhen Xenon ESP8266MOD WiFi smart devices
# E.g. https://wikidevi.com/wiki/Xenon_SM-PW701U
#   SKYROKU SM-PW701U Wi-Fi Plug Smart Plug
#   Wuudi SM-S0301-US - WIFI Smart Power Socket Multi Plug with 4 AC Outlets and 4 USB Charging Works with Alexa
#
# This would not exist without the protocol reverse engineering from
# https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
#
# Tested with Python 2.7 and Python 3.6.1 only

from hashlib import md5
import json
import logging
import socket
import time
import binascii
from pytuya.utils import hex2bin, bin2hex, AESCipher, Colour

log = logging.getLogger(__name__)

SET = 'set'
PROTOCOL_VERSION_BYTES = b'3.1'

# This is intended to match requests.json payload at https://github.com/codetheweb/tuyapi
payload_dict = {
    "device": {
        "status": {
            "hexByte": "0a", "command": {"gwId": "", "devId": ""}
        },
        "set": {
            "hexByte": "07", "command": {"devId": "", "uid": "", "t": ""}
        },
        "prefix": "000055aa00000000000000",
        # Next byte is command byte ("hexByte") some zero padding, then length of remaining payload, i.e. command
        # + suffix (unclear if multiple bytes used for length, zero padding implies could be more than one byte)
        "suffix": "000000000000aa55"
    }
}


class XenonDevice(object):
    def __init__(self, dev_id, address, local_key=None, dev_type='device', connection_timeout=10):
        """ Represents a Tuya device.
        
        Args:
            dev_id (str): The device id.
            address (str): The network address.
            local_key (str, optional): The encryption key. Defaults to None.
            dev_type (str, optional): The device type.
                It will be used as key for lookups in payload_dict.
                Defaults to None.
            
        Attributes:
            port (int): The port to connect to.
        """
        self.id = dev_id
        self.address = address
        self.local_key = local_key.encode('latin1')
        self.dev_type = dev_type
        self.send_receive_max_tries = 3
        self.socket_timeout = connection_timeout / self.send_receive_max_tries
        self.cipher = None
        self.port = 6668  # default - do not expect caller to pass in

    def __repr__(self):
        return '%r' % ((self.id, self.address),)  # FIXME can do better than this

    def _send_receive(self, payload):
        """ Send single buffer `payload` and receive a single buffer.
        
        Args:
            payload(bytes): Data to send.
        """

        success, data = False, ""
        for tries in range(1, self.send_receive_max_tries + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    s.settimeout(self.socket_timeout)
                    s.connect((self.address, self.port))
                    s.send(payload)
                    data = s.recv(1024)
                success = True
                break
            except ConnectionResetError as e:
                logging.warning("Connection attempt %i/%i: %s" % (tries, self.send_receive_max_tries, e))
            except socket.timeout as e:
                logging.warning("Connection attempt %i/%i: %s" % (tries, self.send_receive_max_tries, e))

        if not success:
            raise RuntimeError("Unable to communicate with device")
        else:
            return data

    def generate_payload(self, command, data=None):
        """ Generate the payload to send.

        Args:
            command(str): The type of command. This is one of the entries from payload_dict
            data(dict, optional): The data to be send. This is what will be passed via the 'dps' entry
        """
        json_data = payload_dict[self.dev_type][command]['command'].copy()

        if 'gwId' in json_data:
            json_data['gwId'] = self.id
        if 'devId' in json_data:
            json_data['devId'] = self.id
        if 'uid' in json_data:
            json_data['uid'] = self.id  # still use id, no seperate uid
        if 't' in json_data:
            json_data['t'] = str(int(time.time()))

        if data is not None:
            json_data['dps'] = data

        # Create byte buffer from hex data
        json_payload = json.dumps(json_data)
        json_payload = json_payload.replace(' ', '')  # if spaces are not removed device does not respond!
        json_payload = json_payload.encode('utf-8')
        log.debug('json_payload=%r', json_payload)

        if command == SET:
            # need to encrypt
            self.cipher = AESCipher(self.local_key)  # expect to connect and then disconnect to set new
            json_payload = self.cipher.encrypt(json_payload)
            pre_md5_str = b'data=' + json_payload + b'||lpv=' + PROTOCOL_VERSION_BYTES + b'||' + self.local_key
            m = md5()
            m.update(pre_md5_str)
            json_payload = PROTOCOL_VERSION_BYTES + m.hexdigest()[8:][:16].encode('latin1') + json_payload
            self.cipher = None  # expect to connect and then disconnect to set new

        suffix = payload_dict[self.dev_type]['suffix']
        payload = bin2hex(json_payload)
        crc32 = "%.8x" % binascii.crc32(bytearray(payload.encode()))
        suffix = crc32 + suffix[-8:]
        postfix_payload = hex2bin(payload + suffix)
        postfix_payload_hex_len = '%x' % len(postfix_payload)
        return hex2bin(payload_dict[self.dev_type]['prefix'] + payload_dict[self.dev_type][command]['hexByte'] +
                       '000000' + postfix_payload_hex_len) + postfix_payload


class Device(XenonDevice):
    def status(self):
        log.debug('status() entry')
        # open device, send request, then close connection
        payload = self.generate_payload('status')

        data = self._send_receive(payload)
        log.debug('status received data=%r', data)

        result = data[20:-8]  # hard coded offsets
        log.debug('result=%r', result)
        if result.startswith(b'{'):
            # this is the regular expected code path
            if not isinstance(result, str):
                result = result.decode()
            result = json.loads(result)
        elif result.startswith(PROTOCOL_VERSION_BYTES):
            # got an encrypted payload, happens occasionally
            # expect json to look similar to:: {"devId":"ID","dps":{"1":true,"2":0},"t":EPOCH_SECS,"s":3_DIGIT_NUM}
            # NOTE dps.2 may or may not be present
            result = result[len(PROTOCOL_VERSION_BYTES):]  # remove version header
            result = result[16:]  # remove first 16-bytes - MD5 hexdigest of payload (guess, unconfirmed)
            cipher = AESCipher(self.local_key)
            result = cipher.decrypt(result)
            log.debug('decrypted result=%r', result)
            if not isinstance(result, str):
                result = result.decode()
            result = json.loads(result)
        else:
            log.error('Unexpected status() payload=%r', result)
            result = dict(error=result)

        return result

    def set_status(self, on, switch=1):
        """ Set status of the device to 'on' or 'off'.
        
        Args:
            on(bool):  True for 'on', False for 'off'.
            switch(int): The switch to set
        """
        # open device, send request, then close connection
        if isinstance(switch, int):
            switch = str(switch)  # index and payload is a string
        payload = self.generate_payload(SET, {switch: on})
        # print('payload %r' % payload)

        data = self._send_receive(payload)
        log.debug('set_status received data=%r', data)

        return data

    def turn_on(self, switch=1):
        """ Turn the device on """
        self.set_status(True, switch)

    def turn_off(self, switch=1):
        """ Turn the device off """
        self.set_status(False, switch)

    def set_timer(self, num_secs):
        """ Set a timer.
        
        Args:
            num_secs(int): Number of seconds
        """
        # FIXME / TODO support schemas? Accept timer id number as parameter?

        # Dumb heuristic; Query status, pick last device id as that is probably the timer
        status = self.status()
        devices = status['dps']
        devices_numbers = list(devices.keys())
        devices_numbers.sort()
        dps_id = devices_numbers[-1]

        payload = self.generate_payload(SET, {dps_id: num_secs})

        data = self._send_receive(payload)
        log.debug('set_timer received data=%r', data)
        return data


class OutletDevice(Device):
    def __init__(self, dev_id, address, local_key=None):
        super(OutletDevice, self).__init__(dev_id, address, local_key, dev_type='device')


class BulbDevice(Device):
    DPS_INDEX_ON = '1'
    DPS_INDEX_MODE = '2'
    DPS_INDEX_BRIGHTNESS = '3'
    DPS_INDEX_COLOUR_TEMP = '4'
    DPS_INDEX_COLOUR = '5'
    DPS_INDEX_COLOUR_SCENE = '6'

    DPS = 'dps'
    DPS_MODE_COLOUR = 'colour'
    DPS_MODE_COLOUR_SCENE = 'scene'
    DPS_MODE_WHITE = 'white'

    def __init__(self, dev_id, address, local_key=None):
        dev_type = 'device'
        super(BulbDevice, self).__init__(dev_id, address, local_key, dev_type)

    def _send(self, mode=None, colour=None, brightness=None, colour_temp=None):
        payload_data = {self.DPS_INDEX_MODE: mode,
                        self.DPS_INDEX_COLOUR: colour,
                        self.DPS_INDEX_BRIGHTNESS: brightness,
                        self.DPS_INDEX_COLOUR_TEMP: colour_temp}
        payload = self.generate_payload(SET, {k: v for k, v in payload_data.items() if v is not None})
        return self._send_receive(payload)

    def set_colour(self, r, g, b):
        """ Set colour of an rgb bulb.
        Args:
            r(int): Value for the colour red as int from 0-255.
            g(int): Value for the colour green as int from 0-255.
            b(int): Value for the colour blue as int from 0-255. """

        for value, name in ((r, "red"), (b, "blue"), (g, "green")):
            if not 0 <= value <= 255:
                raise ValueError("The %s for red needs to be between 0 and 255." % name)

        return self._send(self.DPS_MODE_COLOUR, colour=Colour.rgb_to_hex_value(r, g, b))

    def set_white(self, brightness, colour_temp):
        """ Set white coloured theme of an rgb bulb.
        Args:
            brightness(int): Value for the brightness (25-255).
            colour_temp(int): Value for the colour temperature (0-255). """
        if not 25 <= brightness <= 255:
            raise ValueError("The brightness needs to be between 25 and 255.")
        if not 0 <= colour_temp <= 255:
            raise ValueError("The colour temperature needs to be between 0 and 255.")

        return self._send(self.DPS_MODE_WHITE, brightness=brightness, colour_temp=colour_temp)

    def set_brightness(self, brightness):
        """ Set the brightness value of an rgb bulb.
        Args:
            brightness(int): Value for the brightness (25-255). """
        if not 25 <= brightness <= 255:
            raise ValueError("The brightness needs to be between 25 and 255.")

        return self._send(brightness=brightness)

    def set_colour_temp(self, colour_temp):
        """ Set the colour temperature of an rgb bulb.
        Args:
            colour_temp(int): Value for the colour temperature (0-255). """
        if not 0 <= colour_temp <= 255:
            raise ValueError("The colour temperature needs to be between 0 and 255.")

        return self._send(colour_temp=colour_temp)

    def brightness(self):
        """ Return brightness value """
        return self.status().get(self.DPS, {}).get(self.DPS_INDEX_BRIGHTNESS, 0)

    def colour_temp(self):
        """ Return colour temperature """
        return self.status().get(self.DPS, {}).get(self.DPS_INDEX_COLOUR_TEMP, 0)

    def colour_rgb(self):
        """ Return colour as RGB value """
        hex_value = self.status().get(self.DPS, {}).get(self.DPS_INDEX_COLOUR, "0"*6)
        return Colour.hex_value_to_rgb(hex_value)

    def colour_hsv(self):
        """ Return colour as HSV value """
        hex_value = self.status().get(self.DPS, {}).get(self.DPS_INDEX_COLOUR, "0"*14)
        return Colour.hex_value_to_hsv(hex_value)

    def state(self):
        dps = self.status().get(self.DPS, {})
        return {k: v for k, v in
                dict(is_on=dps.get(self.DPS_INDEX_ON),
                     mode=dps.get(self.DPS_INDEX_MODE),
                     brightness=dps.get(self.DPS_INDEX_BRIGHTNESS),
                     colourtemp=dps.get(self.DPS_INDEX_COLOUR_TEMP),
                     colour=dps.get(self.DPS_INDEX_COLOUR)).items() if v is not None}


class CoverDevice(Device):
    action_open = {'2': '1'}
    action_close = {'2': '2'}
    action_stop = {'2': '3'}

    def state(self):
        status = self.status()
        if type(status) is bytes:
            return str(status)
        return {'1': "opening or open", '2': "closing or closed", '3': "stopped"}.get(status.get('dps').get('1'))

    def send_action(self, action):
        payload = self.generate_payload(command=SET, data=action)
        self._send_receive(payload)
        return

    def open(self):
        self.send_action(self.action_open)

    def close(self):
        self.send_action(self.action_close)

    def stop(self):
        self.send_action(self.action_stop)

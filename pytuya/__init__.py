# Python module to interface with Shenzhen Xenon ESP8266MOD WiFi smart devices
# E.g. https://wikidevi.com/wiki/Xenon_SM-PW701U
#   SKYROKU SM-PW701U Wi-Fi Plug Smart Plug
#   Wuudi SM-S0301-US - WIFI Smart Power Socket Multi Plug with 4 AC Outlets and 4 USB Charging Works with Alexa
#
# This would not exist without the protocol reverse engineering from
# https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
#
# Tested with Python 2.7 and Python 3.6.1 only

import base64
from hashlib import md5
import json
import logging
import socket
import sys
import time
import colorsys

try:
    # raise ImportError
    import Crypto
    from Crypto.Cipher import AES  # PyCrypto
except ImportError:
    Crypto = AES = None
    import pyaes  # https://github.com/ricmoo/pyaes

version_tuple = (7, 0, 3)
version = version_string = __version__ = '%d.%d.%d' % version_tuple
__author__ = 'clach04'

log = logging.getLogger(__name__)
logging.basicConfig()  # TODO include function name/line numbers in log
# log.setLevel(level=logging.DEBUG)  # Debug hack!

log.info('Python %s on %s', sys.version, sys.platform)
if Crypto is None:
    log.info('Using pyaes version %r', pyaes.VERSION)
    log.info('Using pyaes from %r', pyaes.__file__)
else:
    log.info('Using PyCrypto %r', Crypto.version_info)
    log.info('Using PyCrypto from %r', Crypto.__file__)

SET = 'set'

PROTOCOL_VERSION_BYTES = b'3.1'

IS_PY2 = sys.version_info[0] == 2


class AESCipher(object):
    def __init__(self, key):
        self.bs = 16
        self.key = key

    def encrypt(self, raw):
        if Crypto:
            raw = self._pad(raw)
            cipher = AES.new(self.key, mode=AES.MODE_ECB)
            crypted_text = cipher.encrypt(raw)
        else:
            _ = self._pad(raw)
            cipher = pyaes.blockfeeder.Encrypter(pyaes.AESModeOfOperationECB(self.key))  # no IV, auto pads to 16
            crypted_text = cipher.feed(raw)
            crypted_text += cipher.feed()  # flush final block
        crypted_text_b64 = base64.b64encode(crypted_text)
        return crypted_text_b64

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        if Crypto:
            cipher = AES.new(self.key, AES.MODE_ECB)
            raw = cipher.decrypt(enc)
            return self._unpad(raw).decode('utf-8')
        else:
            cipher = pyaes.blockfeeder.Decrypter(pyaes.AESModeOfOperationECB(self.key))  # no IV, auto pads to 16
            plain_text = cipher.feed(enc)
            plain_text += cipher.feed()  # flush final block
            return plain_text

    def _pad(self, s):
        padnum = self.bs - len(s) % self.bs
        return s + padnum * chr(padnum).encode()

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


def bin2hex(x, pretty=False):
    space = ' ' if pretty else ''
    if IS_PY2:
        x = [ord(xi) for xi in x]

    return ''.join('%02X%s' % (y, space) for y in x)


def hex2bin(x):
    if IS_PY2:
        return x.decode('hex')
    else:
        return bytes.fromhex(x)


# This is intended to match requests.json payload at https://github.com/codetheweb/tuyapi
payload_dict = {
    "device": {
        "status": {
            "hexByte": "0a",
            "command": {"gwId": "", "devId": ""}
        },
        "set": {
            "hexByte": "07",
            "command": {"devId": "", "uid": "", "t": ""}
        },
        "prefix": "000055aa00000000000000",
        # Next byte is command byte ("hexByte") some zero padding, then length of remaining payload, i.e. command
        # + suffix (unclear if multiple bytes used for length, zero padding implies could be more than one byte)
        "suffix": "000000000000aa55"
    }
}


class XenonDevice(object):
    def __init__(self, dev_id, address, local_key=None, dev_type=None, connection_timeout=10):
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
        self.connection_timeout = connection_timeout
        self.cipher = None
        self.port = 6668  # default - do not expect caller to pass in

    def __repr__(self):
        return '%r' % ((self.id, self.address),)  # FIXME can do better than this

    def _send_receive(self, payload):
        """ Send single buffer `payload` and receive a single buffer.
        
        Args:
            payload(bytes): Data to send.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(self.connection_timeout)
        s.connect((self.address, self.port))
        s.send(payload)
        data = s.recv(1024)
        s.close()
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
            hexdigest = m.hexdigest()
            json_payload = PROTOCOL_VERSION_BYTES + hexdigest[8:][:16].encode('latin1') + json_payload
            self.cipher = None  # expect to connect and then disconnect to set new

        postfix_payload = hex2bin(bin2hex(json_payload) + payload_dict[self.dev_type]['suffix'])

        assert len(postfix_payload) <= 0xff
        postfix_payload_hex_len = '%x' % len(postfix_payload)  # TODO this assumes a single byte 0-255 (0x00-0xff)

        return hex2bin(payload_dict[self.dev_type]['prefix'] + payload_dict[self.dev_type][command]['hexByte'] +
                       '000000' + postfix_payload_hex_len) + postfix_payload


class Device(XenonDevice):
    def __init__(self, dev_id, address, local_key=None, dev_type=None):
        super(Device, self).__init__(dev_id, address, local_key, dev_type)

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
        dev_type = 'device'
        super(OutletDevice, self).__init__(dev_id, address, local_key, dev_type)


class BulbDevice(Device):
    DPS_INDEX_ON = '1'
    DPS_INDEX_MODE = '2'
    DPS_INDEX_BRIGHTNESS = '3'
    DPS_INDEX_COLOURTEMP = '4'
    DPS_INDEX_COLOUR = '5'

    DPS = 'dps'
    DPS_MODE_COLOUR = 'colour'
    DPS_MODE_WHITE = 'white'

    def __init__(self, dev_id, address, local_key=None):
        dev_type = 'device'
        super(BulbDevice, self).__init__(dev_id, address, local_key, dev_type)

    @staticmethod
    def _rgb_to_hexvalue(r, g, b):
        """ Convert an RGB value to the hex representation expected by tuya.
        
        Index '5' (DPS_INDEX_COLOUR) is assumed to be in the format:
        rrggbb0hhhssvv
        
        While r, g and b are just hexadecimal values of the corresponding
        Red, Green and Blue values, the h, s and v values (which are values
        between 0 and 1) are scaled to 360 (h) and 255 (s and v) respectively.
        
        Args:
            r(int): Value for the colour red as int from 0-255.
            g(int): Value for the colour green as int from 0-255.
            b(int): Value for the colour blue as int from 0-255.
        """
        rgb = [r, g, b]
        hsv = colorsys.rgb_to_hsv(rgb[0] / 255, rgb[1] / 255, rgb[2] / 255)

        hexvalue = ""
        for value in rgb:
            temp = str(hex(int(value))).replace("0x", "")
            if len(temp) == 1:
                temp = "0" + temp
            hexvalue = hexvalue + temp

        hsvarray = [int(hsv[0] * 360), int(hsv[1] * 255), int(hsv[2] * 255)]
        hexvalue_hsv = ""
        for value in hsvarray:
            temp = str(hex(int(value))).replace("0x", "")
            if len(temp) == 1:
                temp = "0" + temp
            hexvalue_hsv = hexvalue_hsv + temp
        if len(hexvalue_hsv) == 7:
            hexvalue = hexvalue + "0" + hexvalue_hsv
        else:
            hexvalue = hexvalue + "00" + hexvalue_hsv

        return hexvalue

    @staticmethod
    def _hexvalue_to_rgb(hexvalue):
        """
        Converts the hexvalue used by tuya for colour representation into an RGB value.
        
        Args:
            hexvalue(string): The hex representation generated by BulbDevice._rgb_to_hexvalue()
        """
        r = int(hexvalue[0:2], 16)
        g = int(hexvalue[2:4], 16)
        b = int(hexvalue[4:6], 16)
        return r, g, b

    @staticmethod
    def _hexvalue_to_hsv(hexvalue):
        """
        Converts the hexvalue used by tuya for colour representation into an HSV value.
        
        Args:
            hexvalue(string): The hex representation generated by BulbDevice._rgb_to_hexvalue()
        """
        h = int(hexvalue[7:10], 16) / 360
        s = int(hexvalue[10:12], 16) / 255
        v = int(hexvalue[12:14], 16) / 255

        return (h, s, v)

    def set_colour(self, r, g, b):
        """ Set colour of an rgb bulb.

        Args:
            r(int): Value for the colour red as int from 0-255.
            g(int): Value for the colour green as int from 0-255.
            b(int): Value for the colour blue as int from 0-255.
        """
        if not 0 <= r <= 255:
            raise ValueError("The value for red needs to be between 0 and 255.")
        if not 0 <= g <= 255:
            raise ValueError("The value for green needs to be between 0 and 255.")
        if not 0 <= b <= 255:
            raise ValueError("The value for blue needs to be between 0 and 255.")

        print(BulbDevice)
        hexvalue = BulbDevice._rgb_to_hexvalue(r, g, b)

        payload = self.generate_payload(SET, {
            self.DPS_INDEX_MODE: self.DPS_MODE_COLOUR,
            self.DPS_INDEX_COLOUR: hexvalue})
        data = self._send_receive(payload)
        return data

    def set_white(self, brightness, colourtemp):
        """ Set white coloured theme of an rgb bulb.

        Args:
            brightness(int): Value for the brightness (25-255).
            colourtemp(int): Value for the colour temperature (0-255).
        """
        if not 25 <= brightness <= 255:
            raise ValueError("The brightness needs to be between 25 and 255.")
        if not 0 <= colourtemp <= 255:
            raise ValueError("The colour temperature needs to be between 0 and 255.")

        payload = self.generate_payload(SET, {
            self.DPS_INDEX_MODE: self.DPS_MODE_WHITE,
            self.DPS_INDEX_BRIGHTNESS: brightness,
            self.DPS_INDEX_COLOURTEMP: colourtemp})

        data = self._send_receive(payload)
        return data

    def set_brightness(self, brightness):
        """ Set the brightness value of an rgb bulb.

        Args:
            brightness(int): Value for the brightness (25-255).
        """
        if not 25 <= brightness <= 255:
            raise ValueError("The brightness needs to be between 25 and 255.")

        payload = self.generate_payload(SET, {self.DPS_INDEX_BRIGHTNESS: brightness})
        data = self._send_receive(payload)
        return data

    def set_colourtemp(self, colourtemp):
        """ Set the colour temperature of an rgb bulb.

        Args:
            colourtemp(int): Value for the colour temperature (0-255).
        """
        if not 0 <= colourtemp <= 255:
            raise ValueError("The colour temperature needs to be between 0 and 255.")

        payload = self.generate_payload(SET, {self.DPS_INDEX_COLOURTEMP: colourtemp})
        data = self._send_receive(payload)
        return data

    def brightness(self):
        """ Return brightness value """
        return self.status()[self.DPS][self.DPS_INDEX_BRIGHTNESS]

    def colourtemp(self):
        """ Return colour temperature """
        return self.status()[self.DPS][self.DPS_INDEX_COLOURTEMP]

    def colour_rgb(self):
        """ Return colour as RGB value """
        hexvalue = self.status()[self.DPS][self.DPS_INDEX_COLOUR]
        return BulbDevice._hexvalue_to_rgb(hexvalue)

    def colour_hsv(self):
        """ Return colour as HSV value """
        hexvalue = self.status()[self.DPS][self.DPS_INDEX_COLOUR]
        return BulbDevice._hexvalue_to_hsv(hexvalue)

    def state(self):
        status = self.status()
        state = {
            'is_on': status[self.DPS][self.DPS_INDEX_ON],
            'mode': status[self.DPS][self.DPS_INDEX_MODE],
            'brightness': status[self.DPS][self.DPS_INDEX_BRIGHTNESS],
            'colourtemp': status[self.DPS][self.DPS_INDEX_COLOURTEMP],
            'colour': status[self.DPS][self.DPS_INDEX_COLOUR],
        }
        return state

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


try:
    #raise ImportError
    import Crypto
    from Crypto.Cipher import AES  # PyCrypto
except ImportError:
    Crypto = AES = None
    import pyaes  # https://github.com/ricmoo/pyaes


log = logging.getLogger(__name__)
logging.basicConfig()  # TODO include function name/line numbers in log
#log.setLevel(level=logging.DEBUG)  # Debug hack!

log.debug('Python %s on %s', sys.version, sys.platform)
if Crypto is None:
    log.debug('Using pyaes version %r', pyaes.VERSION)
    log.debug('Using pyaes from %r', pyaes.__file__)
else:
    log.debug('Using PyCrypto %r', Crypto.version_info)
    log.debug('Using PyCrypto from %r', Crypto.__file__)

ON = SET = 'set'
OFF = 'off'

PROTOCOL_VERSION_BYTES = b'3.1'

IS_PY2 = sys.version_info[0] == 2

class AESCipher(object):
    def __init__(self, key):
        #self.bs = 32  # 32 work fines for ON, does not work for OFF. Padding different compared to js version https://github.com/codetheweb/tuyapi/
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
        #print('crypted_text %r' % crypted_text)
        #print('crypted_text (%d) %r' % (len(crypted_text), crypted_text))
        crypted_text_b64 = base64.b64encode(crypted_text)
        #print('crypted_text_b64 (%d) %r' % (len(crypted_text_b64), crypted_text_b64))
        return crypted_text_b64
    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        #print('enc (%d) %r' % (len(enc), enc))
        #enc = self._unpad(enc)
        #enc = self._pad(enc)
        #print('upadenc (%d) %r' % (len(enc), enc))
        if Crypto:
            cipher = AES.new(self.key, AES.MODE_ECB)
            raw = cipher.decrypt(enc)
            #print('raw (%d) %r' % (len(raw), raw))
            return self._unpad(raw).decode('utf-8')
            #return self._unpad(cipher.decrypt(enc)).decode('utf-8')
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
        return s[:-ord(s[len(s)-1:])]


def bin2hex(x, pretty=False):
    if pretty:
        space = ' '
    else:
        space = ''
    if IS_PY2:
        result = ''.join('%02X%s' % (ord(y), space) for y in x)
    else:
        result = ''.join('%02X%s' % (y, space) for y in x)
    return result


def hex2bin(x):
    if IS_PY2:
        return x.decode('hex')
    else:
        return bytes.fromhex(x)

# This is intended to match requests.json payload at https://github.com/codetheweb/tuyapi
payload_dict = {
  "outlet": {
    "status": {
      "hexByte": "0a",
      "command": {"gwId": "", "devId": ""},
    },
    "set": {
      "hexByte": "07",
      "command": {"devId": "", "dps": {"1": True}, "uid": "", "t": ""},  # NOTE dps.1 is a sample and will be overwritten
    },
    "off": {
      "hexByte": "07",
      "command": {"devId": "", "dps": {"1": False}, "uid": "", "t": ""},  # NOTE dps.1 is a sample and will be overwritten
    },
    "prefix": "000055aa00000000000000",    # Next byte is command byte ("hexByte") some zero padding, then length of remaining payload, i.e. command + suffix (unclear if multiple bytes used for length, zero padding implies could be more than one byte)
    "suffix": "000000000000aa55"
  }
}

class XenonDevice(object):
    def __init__(self, dev_id, address, local_key=None, dev_type=None):
        """
        Represents a Tuya device.
        
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
        self.local_key = local_key
        self.local_key = local_key.encode('latin1')
        self.dev_type = dev_type

        self.port = 6668  # default - do not expect caller to pass in

    def __repr__(self):
        return '%r' % ((self.id, self.address),)  # FIXME can do better than this

    def _send_receive(self, payload):
        """
        Send single buffer `payload` and receive a single buffer.
        
        Args:
            payload: Data to send.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.address, self.port))
        s.send(payload)
        data = s.recv(1024)
        s.close()
        return data

    def generate_payload(self, command, dps_id=None, value=None):
        if 'gwId' in payload_dict[self.dev_type][command]['command']:
            payload_dict[self.dev_type][command]['command']['gwId'] = self.id
        if 'devId' in payload_dict[self.dev_type][command]['command']:
            payload_dict[self.dev_type][command]['command']['devId'] = self.id
        if 'uid' in payload_dict[self.dev_type][command]['command']:
            payload_dict[self.dev_type][command]['command']['uid'] = self.id  # still use id, no seperate uid
        if 't' in payload_dict[self.dev_type][command]['command']:
            payload_dict[self.dev_type][command]['command']['t'] = str(int(time.time()))
        if 'dps' in payload_dict[self.dev_type][command]['command']:
            payload_dict[self.dev_type][command]['command']['dps'] = {}

        if command in (SET, ON, OFF):
            if value is None:
                value = True if command == ON else False
            payload_dict[self.dev_type][command]['command']['dps'][dps_id] = value

        # Create byte buffer from hex data
        json_payload = json.dumps(payload_dict[self.dev_type][command]['command'])
        #print(json_payload)
        json_payload = json_payload.replace(' ', '')  # if spaces are not removed device does not respond!
        json_payload = json_payload.encode('utf-8')
        log.debug('json_payload=%r', json_payload)

        if command in (ON, OFF):
            # need to encrypt
            #print('json_payload %r' % json_payload)
            self.cipher = AESCipher(self.local_key)  # expect to connect and then disconnect to set new
            json_payload = self.cipher.encrypt(json_payload)
            #print('crypted json_payload %r' % json_payload)
            preMd5String = b'data=' + json_payload + b'||lpv=' + PROTOCOL_VERSION_BYTES + b'||' + self.local_key
            #print('preMd5String %r' % preMd5String)
            m = md5()
            m.update(preMd5String)
            #print(repr(m.digest()))
            hexdigest = m.hexdigest()
            #print(hexdigest)
            #print(hexdigest[8:][:16])
            json_payload = PROTOCOL_VERSION_BYTES + hexdigest[8:][:16].encode('latin1') + json_payload
            #print('data_to_send')
            #print(json_payload)
            #print('crypted json_payload (%d) %r' % (len(json_payload), json_payload))
            #print('json_payload  %r' % repr(json_payload))
            #print('json_payload len %r' % len(json_payload))
            #print(bin2hex(json_payload))
            self.cipher = None  # expect to connect and then disconnect to set new


        postfix_payload = hex2bin(bin2hex(json_payload) + payload_dict[self.dev_type]['suffix'])
        #print('postfix_payload %r' % postfix_payload)
        #print('postfix_payload %r' % len(postfix_payload))
        #print('postfix_payload %x' % len(postfix_payload))
        #print('postfix_payload %r' % hex(len(postfix_payload)))
        assert len(postfix_payload) <= 0xff
        postfix_payload_hex_len = '%x' % len(postfix_payload)  # TODO this assumes a single byte 0-255 (0x00-0xff)
        buffer = hex2bin(payload_dict[self.dev_type]['prefix'] + payload_dict[self.dev_type][command]['hexByte'] + '000000' + postfix_payload_hex_len) + postfix_payload
        #print('command', command)
        #print('prefix')
        #print(payload_dict[self.dev_type][command]['prefix'])
        #print(repr(buffer))
        #print(bin2hex(buffer, pretty=True))
        #print(bin2hex(buffer, pretty=False))
        #print('full buffer(%d) %r' % (len(buffer), buffer))
        return buffer


class OutletDevice(XenonDevice):
    def __init__(self, dev_id, address, local_key=None, dev_type=None):
        dev_type = dev_type or 'outlet'
        super(OutletDevice, self).__init__(dev_id, address, local_key, dev_type)

    def status(self):
        log.debug('status() entry')
        # open device, send request, then close connection
        payload = self.generate_payload('status')

        data = self._send_receive(payload)
        log.debug('status received data=%r', data)

        result = data[20:-8]  # hard coded offsets
        log.debug('result=%r', result)
        #result = data[data.find('{'):data.rfind('}')+1]  # naive marker search, hope neither { nor } occur in header/footer
        #print('result %r' % result)
        if result.startswith(b'{'):
            # this is the regular expected code path
            result = json.loads(result.decode())
        elif result.startswith(PROTOCOL_VERSION_BYTES):
            # got an encrypted payload, happens occasionally
            # expect resulting json to look similar to:: {"devId":"ID","dps":{"1":true,"2":0},"t":EPOCH_SECS,"s":3_DIGIT_NUM}
            # NOTE dps.2 may or may not be present
            result = result[len(PROTOCOL_VERSION_BYTES):]  # remove version header
            result = result[16:]  # remove (what I'm guessing, but not confirmed is) 16-bytes of MD5 hexdigest of payload
            cipher = AESCipher(self.local_key)
            result = cipher.decrypt(result)
            log.debug('decrypted result=%r', result)
            result = json.loads(result.decode())
        else:
            log.error('Unexpected status() payload=%r', result)

        return result

    def set_status(self, on, switch=1):
        """
        Set status of the device to ON or OFF.
        
        Args:
            on(bool):  True for ON, False for OFF.
        """
        # open device, send request, then close connection
        command = ON if on else OFF
        if isinstance(switch, int):
            switch = str(switch)  # index and payload is a string
        payload = self.generate_payload(command, dps_id=switch)
        #print('payload %r' % payload)

        data = self._send_receive(payload)
        log.debug('set_status received data=%r', data)

        return data

    def set_timer(self, num_secs):
        """
        Set a timer.
        
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
        command = SET
        payload = self.generate_payload(command, dps_id=dps_id, value=num_secs)

        data = self._send_receive(payload)
        log.debug('set_timer received data=%r', data)
        return data


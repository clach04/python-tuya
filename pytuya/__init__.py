# Python module to interface with Shenzhen Xenon ESP8266MOD WiFi smart devices
# E.g. https://wikidevi.com/wiki/Xenon_SM-PW701U
#   SKYROKU SM-PW701U Wi-Fi Plug Smart Plug
#   Wuudi SM-S0301-US - WIFI Smart Power Socket Multi Plug with 4 AC Outlets and 4 USB Charging Works with Alexa
#
# This would not exist without the protocol reverse engineering from
# https://github.com/codetheweb/tuyapi by codetheweb and blackrozes
#
# Currently Python 2.x only


import base64
from hashlib import md5
import json
import socket
import time


try:
    #raise ImportError
    from Crypto.Cipher import AES  # PyCrypto
except ImportError:
    AES = None
    import pyaes  # https://github.com/ricmoo/pyaes



ON = 'on'
OFF = 'off'

class AESCipher(object):
    def __init__(self, key):
        #self.bs = 32  # 32 work fines for ON, does not work for OFF. Padding different compared to js version https://github.com/codetheweb/tuyapi/
        self.bs = 16
        self.key = key
    def encrypt(self, raw):
        if AES:
            raw = self._pad(raw)
            cipher = AES.new(self.key, mode=AES.MODE_ECB, IV='')
            crypted_text = cipher.encrypt(raw)
        else:
            cipher = pyaes.blockfeeder.Encrypter(pyaes.AESModeOfOperationECB(self.key))  # no IV, auto pads to 16
            crypted_text = cipher.feed(raw)
            crypted_text += cipher.feed()  # flush final block
        #print('crypted_text %r' % crypted_text)
        return base64.b64encode(crypted_text)
    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_ECB)
        return self._unpad(cipher.decrypt(enc)).decode('utf-8')
    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


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
      "command": {"devId": "", "dps": {"1": True}, "uid": "", "t": ""},  ## FIXME "1"
      "suffix": "000000000000aa55"
    },
    "off": {
      "prefix": "000055aa0000000000000007000000b3",
      "command": {"devId": "", "dps": {"1": False}, "uid": "", "t": ""},  ## FIXME "1"
      "suffix": "000000000000aa55"
    }
  }
}

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

        self.port = 6668  # default - do not expect caller to pass in
        self.version = 3.1  # default - do not expect caller to pass in

    def generate_payload(self, command, dps_id=None):
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

        if command in (ON, OFF):
            switch_state = True if command == ON else False
            payload_dict[self.dev_type][command]['command']['dps'][dps_id] = switch_state

        # Create byte buffer from hex data
        json_payload = json.dumps(payload_dict[self.dev_type][command]['command']).encode('utf-8')
        #print(json_payload)
        json_payload = json_payload.replace(' ', '')  # if spaces are not removed device does not respond!
        #print(json_payload)

        if command in (ON, OFF):
            # need to encrypt
            #print('json_payload %r' % json_payload)
            self.cipher = AESCipher(self.local_key)  # expect to connect and then disconnect to set new
            json_payload = self.cipher.encrypt(json_payload)
            #print('crypted json_payload %r' % json_payload)
            preMd5String = 'data=' + json_payload + '||lpv=' + str(self.version) + '||' + self.local_key
            #print('preMd5String %r' % preMd5String)
            m = md5()
            m.update(preMd5String)
            #print(repr(m.digest()))
            hexdigest = m.hexdigest()
            #print(hexdigest)
            #print(hexdigest[8:][:16])
            json_payload = str(self.version) + hexdigest[8:][:16] + json_payload
            #print('data_to_send')
            #print(json_payload)
            #print(bin2hex(json_payload))
            self.cipher = None  # expect to connect and then disconnect to set new


        buffer = payload_dict[self.dev_type][command]['prefix'] + bin2hex(json_payload) + payload_dict[self.dev_type][command]['suffix']
        buffer = hex2bin(buffer)
        #print('command', command)
        #print('prefix')
        #print(payload_dict[self.dev_type][command]['prefix'])
        #print(repr(buffer))
        #print(bin2hex(buffer, pretty=True))
        #print(bin2hex(buffer, pretty=False))
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

    def set_status(self, on, switch=1):
        # open device, send request, then close connection
        command = ON if on else OFF
        if isinstance(switch, int):
            switch = str(switch)  # index and payload is a string
        payload = self.generate_payload(command, dps_id=switch)
        #print('payload %r' % payload)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.address, self.port))
        s.send(payload)
        data = s.recv(1024)
        s.close()
        return data

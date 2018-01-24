import unittest
try:
    # Python 3 only
    from unittest.mock import MagicMock
except ImportError:
    # for py2 use https://pypi.python.org/pypi/mock
    from mock import MagicMock
from hashlib import md5
import pytuya
import json
import logging
import codecs

LOCAL_KEY = '0123456789abcdef'

mock_byte_encoding = 'utf-8'

def compare_json_strings(json1, json2, ignoring_keys=None):
    json1 = json.loads(json1)
    json2 = json.loads(json2)

    if ignoring_keys is not None:
        for key in ignoring_keys:
            json1[key] = json2[key]

    return json.dumps(json1, sort_keys=True) == json.dumps(json2, sort_keys=True)

def check_data_frame(data, expected_prefix, encrypted=True):
    prefix = data[:15]
    suffix = data[-8:]
    
    if encrypted:
        payload_len = int(codecs.encode(data[15:16], 'hex'), 16)
        version = data[16:19]
        checksum = data[19:35]
        encrypted_json = data[35:-8]
        
        json_data = pytuya.AESCipher(LOCAL_KEY.encode('utf-8')).decrypt(encrypted_json)
    else:
        json_data = data[16:-8].decode('utf-8')
    
    frame_ok = True
    if prefix != pytuya.hex2bin(expected_prefix):
        frame_ok = False
    elif suffix != pytuya.hex2bin("000000000000aa55"):
        frame_ok = False
    elif encrypted:
        if payload_len != len(version) + len(checksum) + len(encrypted_json) + len(suffix):
            frame_ok = False
        elif version != b"3.1":
            frame_ok = False
    
    return json_data, frame_ok
            
def mock_send_receive_set_timer(data):
    if mock_send_receive_set_timer.call_counter == 0:
        ret = 20*chr(0x0) + '{"devId":"DEVICE_ID","dps":{"1":false,"2":0}}' + 8*chr(0x0)
    elif mock_send_receive_set_timer.call_counter == 1:
        expected = '{"uid":"DEVICE_ID_HERE","devId":"DEVICE_ID_HERE","t":"","dps":{"2":6666}}'
        json_data, frame_ok = check_data_frame(data, "000055aa0000000000000007000000")
        
        if frame_ok and compare_json_strings(json_data, expected, ['t']):
            ret = '{"test_result":"SUCCESS"}'
        else:
            ret = '{"test_result":"FAIL"}'

    ret = ret.encode(mock_byte_encoding)
    mock_send_receive_set_timer.call_counter += 1
    return ret
    
def mock_send_receive_set_status(data):
    expected = '{"dps":{"1":true},"uid":"DEVICE_ID_HERE","t":"1516117564","devId":"DEVICE_ID_HERE"}'
    json_data, frame_ok = check_data_frame(data, "000055aa0000000000000007000000")
    
    if frame_ok and compare_json_strings(json_data, expected, ['t']):
        ret = '{"test_result":"SUCCESS"}'
    else:
        logging.error("json data not the same: {} != {}".format(json_data, expected))
        ret = '{"test_result":"FAIL"}'

    ret = ret.encode(mock_byte_encoding)
    return ret

def mock_send_receive_status(data):
    expected = '{"devId":"DEVICE_ID_HERE","gwId":"DEVICE_ID_HERE"}'
    json_data, frame_ok = check_data_frame(data, "000055aa000000000000000a000000", False)

    # FIXME dead code block
    if frame_ok and compare_json_strings(json_data, expected):
        ret = '{"test_result":"SUCCESS"}'
    else:
        logging.error("json data not the same: {} != {}".format(json_data, expected))
        ret = '{"test_result":"FAIL"}'

    ret = 20*chr(0) + ret + 8*chr(0)
    ret = ret.encode(mock_byte_encoding)
    return ret

class TestXenonDevice(unittest.TestCase):
    def test_set_timer(self):
        d = pytuya.OutletDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d._send_receive = MagicMock(side_effect=mock_send_receive_set_timer)
        
        # Reset call_counter and start test
        mock_send_receive_set_timer.call_counter = 0
        result = d.set_timer(6666)
        result = result[result.find(b'{'):result.rfind(b'}')+1]
        result = json.loads(result)
        
        # Make sure mock_send_receive_set_timer() has been called twice with correct parameters
        self.assertEqual(result['test_result'], "SUCCESS")
        
    def test_set_status(self):
        d = pytuya.OutletDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d._send_receive = MagicMock(side_effect=mock_send_receive_set_status)
        
        result = d.set_status(True, 1)
        result = json.loads(result)
        
        # Make sure mock_send_receive_set_timer() has been called twice with correct parameters
        self.assertEqual(result['test_result'], "SUCCESS")

    def test_status(self):
        d = pytuya.OutletDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d._send_receive = MagicMock(side_effect=mock_send_receive_status)

        result = d.status()

        # Make sure mock_send_receive_set_timer() has been called twice with correct parameters
        self.assertEqual(result['test_result'], "SUCCESS")

if __name__ == '__main__':
    unittest.main()
#!/usr/bin/env python3

import json
import logging
import struct
import pytuya
import unittest

try:
    from unittest.mock import MagicMock  # Python 3
except ImportError:
    from mock import MagicMock  # py2 use https://pypi.python.org/pypi/mock


# Enable info logging to see version information
log = logging.getLogger('pytuya')
log.setLevel(level=logging.INFO)
# log.setLevel(level=logging.DEBUG)  # Debug hack!

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
        payload_len = struct.unpack(">B", data[15:16])[0]  # big-endian, unsigned char
        version = data[16:19]
        checksum = data[19:35]
        encrypted_json = data[35:-8]
        json_data = pytuya.utils.AESCipher(LOCAL_KEY.encode(mock_byte_encoding)).decrypt(encrypted_json)
    else:
        json_data = data[16:-8].decode(mock_byte_encoding)

    frame_ok = True
    if prefix != pytuya.utils.hex2bin(expected_prefix):
        frame_ok = False
    elif suffix != pytuya.utils.hex2bin("000000000000aa55"):
        frame_ok = False
    elif encrypted:
        if payload_len != len(version) + len(checksum) + len(encrypted_json) + len(suffix):
            frame_ok = False
        elif version != b"3.1":
            frame_ok = False

    return json_data, frame_ok


def mock_send_receive_set_timer(data):
    if not hasattr(mock_send_receive_set_timer, "call_counter"):
        mock_send_receive_set_timer.call_counter = 0
    if mock_send_receive_set_timer.call_counter == 0:
        ret = 20 * chr(0x0) + '{"devId":"DEVICE_ID","dps":{"1":false,"2":0}}' + 8 * chr(0x0)
    elif mock_send_receive_set_timer.call_counter == 1:
        expected = '{"uid":"ID","devId":"ID","t":"","dps":{"2":6666}}'
        json_data, frame_ok = check_data_frame(data, "000055aa0000000000000007000000")

        if frame_ok and compare_json_strings(json_data, expected, ['t']):
            ret = '{"test_result":"SUCCESS"}'
        else:
            ret = '{"test_result":"FAIL"}'
    else:
        raise RuntimeError("unexpected counter of > 1")

    ret = ret.encode(mock_byte_encoding)
    mock_send_receive_set_timer.call_counter += 1
    return ret


def mock_send_receive_set_status(data):
    expected = '{"dps":{"1":true},"uid":"ID","t":"1516117564","devId":"ID"}'
    json_data, frame_ok = check_data_frame(data, "000055aa0000000000000007000000")

    if frame_ok and compare_json_strings(json_data, expected, ['t']):
        ret = '{"test_result":"SUCCESS"}'
    else:
        logging.error("json data not the same: {} != {}".format(json_data, expected))
        ret = '{"test_result":"FAIL"}'

    ret = ret.encode(mock_byte_encoding)
    return ret


def mock_send_receive_status(data):
    expected = '{"devId":"ID","gwId":"ID"}'
    json_data, frame_ok = check_data_frame(data, "000055aa000000000000000a000000", False)

    # FIXME dead code block
    if frame_ok and compare_json_strings(json_data, expected):
        ret = '{"test_result":"SUCCESS"}'
    else:
        logging.error("json data not the same: {} != {}".format(json_data, expected))
        ret = '{"test_result":"FAIL"}'

    ret = 20 * chr(0) + ret + 8 * chr(0)
    ret = ret.encode(mock_byte_encoding)
    return ret


def mock_send_receive_set_colour(data):
    expected = '{"dps":{"2":"colour", "5":"ffffff000000ff"}, "devId":"ID","uid":"ID", "t":"1516117564"}'

    json_data, frame_ok = check_data_frame(data, "000055aa0000000000000007000000")

    if frame_ok and compare_json_strings(json_data, expected, ['t']):
        ret = '{"test_result":"SUCCESS"}'
    else:
        logging.error("json data not the same: {} != {}".format(json_data, expected))
        ret = '{"test_result":"FAIL"}'

    ret = ret.encode(mock_byte_encoding)
    return ret


def mock_send_receive_set_white(data):
    expected = '{"dps":{"2":"white", "3":255, "4":255}, "devId":"ID","uid":"ID", "t":"1516117564"}'
    json_data, frame_ok = check_data_frame(data, "000055aa0000000000000007000000")

    if frame_ok and compare_json_strings(json_data, expected, ['t']):
        ret = '{"test_result":"SUCCESS"}'
    else:
        logging.error("json data not the same: {} != {}".format(json_data, expected))
        ret = '{"test_result":"FAIL"}'

    ret = ret.encode(mock_byte_encoding)
    return ret


class TestXenonDevice(unittest.TestCase):
    def test_set_timer(self):
        d = pytuya.OutletDevice('ID', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d._send_receive = MagicMock(side_effect=mock_send_receive_set_timer)

        # Reset call_counter and start test
        mock_send_receive_set_timer.call_counter = 0
        result = d.set_timer(6666)
        result = result[result.find(b'{'):result.rfind(b'}') + 1]
        result = result.decode(
            mock_byte_encoding)  # Python 3 (3.5.4 and earlier) workaround to json stdlib "behavior" https://docs.python.org/3/whatsnew/3.6.html#json
        result = json.loads(result)

        # Make sure mock_send_receive_set_timer() has been called twice with correct parameters
        self.assertEqual(result['test_result'], "SUCCESS")

    def test_set_status(self):
        d = pytuya.OutletDevice('ID', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d._send_receive = MagicMock(side_effect=mock_send_receive_set_status)

        result = d.set_status(True, 1)
        result = result.decode(
            mock_byte_encoding)  # Python 3 (3.5.4 and earlier) workaround to json stdlib "behavior" https://docs.python.org/3/whatsnew/3.6.html#json
        result = json.loads(result)

        # Make sure mock_send_receive_set_timer() has been called twice with correct parameters
        self.assertEqual(result['test_result'], "SUCCESS")

    def test_status(self):
        d = pytuya.OutletDevice('ID', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d._send_receive = MagicMock(side_effect=mock_send_receive_status)

        result = d.status()

        # Make sure mock_send_receive_set_timer() has been called twice with correct parameters
        self.assertEqual(result['test_result'], "SUCCESS")

    def test_set_colour(self):
        d = pytuya.BulbDevice('ID', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d._send_receive = MagicMock(side_effect=mock_send_receive_set_colour)

        result = d.set_colour(255, 255, 255)
        result = result.decode(mock_byte_encoding)
        result = json.loads(result)

        self.assertEqual(result['test_result'], "SUCCESS")

    def test_set_white(self):
        d = pytuya.BulbDevice('ID', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d._send_receive = MagicMock(side_effect=mock_send_receive_set_white)

        result = d.set_white(255, 255)
        result = result.decode(mock_byte_encoding)
        result = json.loads(result)

        self.assertEqual(result['test_result'], "SUCCESS")


if __name__ == '__main__':
    unittest.main()

import unittest
from unittest.mock import MagicMock
import pytuya
import json
import logging

LOCAL_KEY = '0123456789abcdef'

def compare_json_strings(json1, json2, ignoring_keys=None):
    json1 = json.loads(json1)
    json2 = json.loads(json2)

    if ignoring_keys is not None:
        for key in ignoring_keys:
            json1[key] = json2[key]

    return json.dumps(json1, sort_keys=True) == json.dumps(json2, sort_keys=True)

def mock_send_receive_set_timer(data):
    if mock_send_receive_set_timer.call_counter == 0:
        ret = 20*chr(0x0) + '{"devId":"DEVICE_ID","dps":{"1":false,"2":0}}' + 8*chr(0x0)
    elif mock_send_receive_set_timer.call_counter == 1:
        expected = '{"uid":"DEVICE_ID_HERE","devId":"DEVICE_ID_HERE","t":"","dps":{"2":6666}}'
        json_data = pytuya.AESCipher(LOCAL_KEY.encode('utf-8')).decrypt(data[35:-8])
        
        if compare_json_strings(json_data, expected, ['t']):
            ret = '{"test_result":"SUCCESS"}'
        else:
            ret = '{"test_result":"FAIL"}'
        
    mock_send_receive_set_timer.call_counter += 1
    return ret
    
def mock_send_receive_set_status(data):
    expected = '{"dps":{"1":true},"uid":"DEVICE_ID_HERE","t":"1516117564","devId":"DEVICE_ID_HERE"}'
    json_data = pytuya.AESCipher(LOCAL_KEY.encode('utf-8')).decrypt(data[35:-8])
    
    if compare_json_strings(json_data, expected, ['t']):
        ret = '{"test_result":"SUCCESS"}'
    else:
        logging.error("json data not the same: {} != {}".format(json_data, expected))
        ret = '{"test_result":"FAIL"}'
        
    return ret

class TestXenonDevice(unittest.TestCase):
    def test_set_timer(self):
        d = pytuya.OutletDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', LOCAL_KEY)
        d._send_receive = MagicMock(side_effect=mock_send_receive_set_timer)
        
        # Reset call_counter and start test
        mock_send_receive_set_timer.call_counter = 0
        result = d.set_timer(6666)
        result = result[result.find('{'):result.rfind('}')+1]
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

if __name__ == '__main__':
    unittest.main()
# python-tuya

[![Build Status](https://travis-ci.org/clach04/python-tuya.svg?branch=master)](https://travis-ci.org/clach04/python-tuya)

Python 2.7 and Python 3.6.1 interface to ESP8266MOD WiFi smart devices from Shenzhen Xenon.
If you are using the Jinvoo Smart app, this allows local control over the LAN.
NOTE requires the devices to have already been **activated** by Jinvoo Smart app (or similar).


Known to work with:
  * SKYROKU SM-PW701U Wi-Fi Plug Smart Plug - see https://wikidevi.com/wiki/Xenon_SM-PW701U
  * Wuudi SM-S0301-US - WIFI Smart Power Socket Multi Plug with 4 AC Outlets and 4 USB Charging
  * Jinvoo WiFi Curtain / Roller Shutter Switch


## Key extraction

- background knowledge
  - The ``local-key`` is used for AES-based encryption of the messages sent between device and client. 
  - Key changes every time the device is reset and paired to a new account (e.g. using app)
  - Key and further meta-data is regularly requested by the app from the cloud-server via HTTPS requests 
  - The request responses can be recorded by apps to extract the key and further data (such as name, ip, state, etc.)
- how to extract key
  - Android
    - Install your app used for setup and paring (tested with TuyaSmart)
    - Install [SSL Capture](https://play.google.com/store/apps/details?id=com.minhui.networkcapture)
    - Change app settings to only record your pairing app and start recording
    - Go inside app and do something with one of your devices
    - Go back inside the SSL Capture app, stop the recording
    - Find the package with the longest response by the server
    - Copy all information from the response body to your computer (e.g. via email)
    - Use pytuya to extract key from the response stored inside a file:
      ``pytuya extract response.txt``
  - IOS 
    - > TODO

- further resources:
  - https://github.com/clach04/python-tuya/wiki has further information for how to get device id and local key.
(the device id can be seen in Jinvoo Smart app, under "Device Info").

## CLI-Demo

## API-Demo:

    import pytuya

    d = pytuya.OutletDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', 'LOCAL_KEY_HERE')
    data = d.status()  # NOTE this does NOT require a valid key
    print('Dictionary %r' % data)
    print('state (bool, true is ON) %r' % data['dps']['1'])  # Show status of first controlled switch on device

    # Toggle switch state
    switch_state = data['dps']['1']
    data = d.set_status(not switch_state)  # This requires a valid key
    if data:
        print('set_status() result %r' % data)

    # on a switch that has 4 controllable ports, turn the fourth OFF (1 is the first)
    data = d.set_status(False, 4)
    if data:
        print('set_status() result %r' % data)
        print('set_status() extrat %r' % data[20:-8])

TODO demo timer (with comment not all devices support this, one way to check, is to check Jinvoo Smart App and see if there is a clock icon that is not dimmed out).

### Encryption notes

These devices uses AES encryption, this is not available in Python standard library, there are three options:

 1) PyCrypto
 2) PyCryptodome
 3) pyaes (note Python 2.x support requires https://github.com/ricmoo/pyaes/pull/13)

### Related Projects

  * https://github.com/sean6541/tuyaapi Python API to the web api
  * https://github.com/codetheweb/tuyapi node.js
  * https://github.com/Marcus-L/m4rcus.TuyaCore - .NET
  * https://github.com/SDNick484/rectec_status/ - RecTec pellet smokers control (with Alexa skill)

### Acknowledgements

  * Major breakthroughs on protocol work came from https://github.com/codetheweb/tuyapi from the reverse engineering time and skills of codetheweb and blackrozes, additional protocol reverse engineering from jepsonrob and clach04.
  * nijave pycryptodome support and testing
  * Exilit for unittests and docstrings
  * mike-gracia for improved Python version support
  * samuscherer for RGB Bulb support
  * magneticflux- for improved Python version support
  * sean6541 - for initial PyPi package and Home Assistant support <https://github.com/sean6541/tuya-homeassistant>

# python-tuya

Python interface to ESP8266MOD WiFi smart devices from Shenzhen Xenon

All protocol work came from https://github.com/codetheweb/tuyapi from the reverse engineering time and skills of codetheweb and blackrozes.


Demo:

    import pytuya

    # See https://github.com/codetheweb/tuyapi/blob/master/docs/SETUP.md for how to get device id
    d = pytuya.OutletDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE')
    data = d.status()
    print('Dictionary %r' % data)
    print('state (bool, true is ON) %r' % data['dps']['1'])  # Show status of first controlled switch on device

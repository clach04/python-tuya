# python-tuya

Python Python 2.7 and Python 3.6.1 interface to ESP8266MOD WiFi smart devices from Shenzhen Xenon.
If you are using the Jinvoo Smart App, this allows local control over the LAN.
NOTE requires the devices to have already been activated by Jinvoo Smart App.

https://github.com/clach04/python-tuya/wiki has background innformation.
See https://github.com/codetheweb/tuyapi/blob/master/docs/SETUP.md for how to get device id and local key.
(the device id can be seen in Jinvoo Smart App, under "Device Info").

All protocol work came from https://github.com/codetheweb/tuyapi from the reverse engineering time and skills of codetheweb and blackrozes.

Known to work with:
  * SKYROKU SM-PW701U Wi-Fi Plug Smart Plug - see https://wikidevi.com/wiki/Xenon_SM-PW701U
  * Wuudi SM-S0301-US - WIFI Smart Power Socket Multi Plug with 4 AC Outlets and 4 USB Charging


Demo:

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

# WiFi Deauther

Python tool for scanning Wi-Fi networks and sending deauthentication packets.

>[!WARNING]
>Use only on authorized networks.

---

## Features

* Scan access points and clients
* `all` or `one` mode
* Interactive target selection
* Automatic channel hopping
* Filtering (whitelist, CLI options)

---

## Usage

```bash
sudo python3 wifijammer.py
```

### Examples

```bash
sudo python3 wifijammer.py --target all
sudo python3 wifijammer.py --target one
sudo python3 wifijammer.py -i wlan0mon
sudo python3 wifijammer.py --target one -a xx:xx:xx:xx:xx:xx
```

---

## Requirements

* Python 3
* Scapy
* Wi-Fi card with monitor mode support
* Linux

---

## License

[License](LICENSE)
>Based on an original project by Dan McInerney, modified by MeiosisKMZ.

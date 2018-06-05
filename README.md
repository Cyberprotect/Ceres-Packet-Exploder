![](https://www.cyberprotect.fr/wp-content/uploads/2015/12/Logo-340-156-web-noir.png)

> Rémi ALLAIN <rallain@cyberprotect.fr>

# Ceres Packet exploder

A python script for extracting observables from pcap.

### Installation

```bash
git clone 'https://github.com/Cyberprotect/Ceres-Packet-Exploder.git'
cd Ceres-Packet-Exploder-master
python setup.py install
```

or

```bash
pip install cerespacketexploder
```


### Usage

```python
from cerespacketexploder.api import ceres

pcap = 'sample.pcap'

config = {
    'parser': {
        'http': {
            'chaosreader': '/usr/bin/chaosreader'
        }
    },
    'storage': './Storage/Ceres',
    'supported_pcap_types': [
        'application/vnd.tcpdump.pcap',
        'application/octet-stream'
    ]
}

c = ceres(pcap, config)

observables = c.run()
print(observables)

```

### Result

```json
[
    {
        "dataType": "service",
        "data": "http",
        "childs": [
            {
                "dataType": "session",
                "data": "0245",
                "childs": [
                    {
                        "dataType": "hash",
                        "data": "4477039d5decdf4706e32b57977b1d6b80cbf0feb929c2bcb43e44aa34cb85a5"
                    },
                    {
                        "dataType": "hash",
                        "data": "07bf52db2e9869573e613312083c4580"
                    },
                    {
                        "dataType": "filename",
                        "data": "invoice.pdf"
                    },
                    {
                        "dataType": "file",
                        "data": "./Storage/Ceres/fa1227c7-e849-4026-9d1c-7a391f892e03/http/sample.pcap.sessions/session_0245.part_01.pdf"
                    },
                    {
                        "dataType": "url",
                        "data": "http://intranet.company.net/download/invoice.pdf"
                    },
                    {
                        "dataType": "domain",
                        "data": "intranet.company.net"
                    },
                    {
                        "dataType": "ip",
                        "data": "192.168.1.1"
                    },
                    {
                        "dataType": "ip",
                        "data": "172.16.1.1"
                    },
                    {
                        "dataType": "date",
                        "data": "2018-01-01 10:00:00"
                    }
                ]
            }
        ]
    }
]
```
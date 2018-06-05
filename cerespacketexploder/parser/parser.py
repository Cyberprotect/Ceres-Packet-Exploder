
#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Class definition for parsers"""

import os


class parser:
    """
    Class definition for parsers
    """

    pcap_filename = None
    config = None
    storage = None

    def __init__(self, pcap_filename, config, storage):
        self.pcap_filename = pcap_filename
        self.config = config
        self.storage = storage
        if(not os.path.exists(self.storage)):
            os.makedirs(self.storage)

    def explode(self):
        raise NotImplementedError('"explode()" method not implemented in the parser class')

    def report(self):
        raise NotImplementedError('"report()" method not implemented in the parser class')

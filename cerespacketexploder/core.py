
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, unicode_literals
import argparse
import hashlib
import json
import os
import re
import sys
import uuid
import magic
import moment
# Local import
from utils import utils
from parser.http import http as parser_http
from parser.parser import parser as parser_parent

"""Utils module"""

class ceres:
    """
    Class used to explode a pcap and retrieve observables thanks to specific parsers
    """

    config = None
    uuid = None
    pcap_filename = None
    storage = None
    supported_pcap_type = None
    parsers = {}

    def __init__(self, pcap_filename, config):

        self.config = config
        self.pcap_filename = pcap_filename

        if(not self.config.get('supported_pcap_types')):
            raise AttributeError(
                'Value "supported_pcap_types" not found in the configuration file.')
        self.supported_pcap_type = self.config.get('supported_pcap_types')

        if not utils.check_mime_type(self.pcap_filename, self.supported_pcap_type):
            raise ValueError('{} doesn\'t appear to be a pcap supported by ceres. Supported = {}'.format(
                self.pcap_filename, self.supported_pcap_type))

        self.uuid = utils.generate_uuid()

        if(not self.config.get('storage')):
            raise AttributeError(
                'Value "storage" not found in the configuration file.')

        self.storage = os.path.realpath(
            '{}/{}/'.format(self.config.get('storage'), self.uuid))

        if(not os.path.exists(self.storage)):
            os.makedirs(self.storage)

        self.declare_parsers()

    def declare_parsers(self):
        """
        Method to instanciate parsers
        """
        # parser http:
        self.parsers['http'] = parser_http(self.pcap_filename, self.config['parser']['http'], self.storage+'/http/')
        
        # parser ftp:
        self.parsers['ftp'] = None

        # parser smb:
        self.parsers['smb'] = None

        # parser smtp:
        self.parsers['smtp'] = None


    def run(self):
        """
        Run each parser and add their report to the final result
        """
        output = []

        for parser_name in self.parsers:
            parser = self.parsers.get(parser_name)
            if isinstance(parser, parser_parent):
                parser.explode()
                output += [
                    {
                        "data": parser_name,
                        "dataType": "service",
                        "childs": parser.report()
                    }
                ]
                #output[parser_name] = parser.report()

        return output

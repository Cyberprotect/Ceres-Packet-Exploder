#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Observable structure"""


class observable:
    """Observable structure"""

    data = ""
    dataType = ""
    childs = []

    def __init__(self, data="", dataType="",childs=[]):
        self.data = data
        self.dataType = dataType
        self.childs = childs
        
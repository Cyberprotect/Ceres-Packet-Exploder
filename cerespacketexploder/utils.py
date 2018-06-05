#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, unicode_literals
import os
import magic
import json
import hashlib
import uuid

"""Utils module"""


class utils:
    """
    Regroupment of useful functions
    All methods are static
    """

    @staticmethod
    def check_mime_type(filename, mime_type_allowed):
        """
        Check if the mime type of the file is in the allowed type
        Return bool valid
        """
        if not isinstance(mime_type_allowed, (list, tuple)):
            raise TypeError('"mime_type_allowed" is not a list or a tuple')
        mime_type = magic.from_file(filename, mime=True)
        if(mime_type in mime_type_allowed):
            return True
        return False

    @staticmethod
    def generate_uuid():
        """
        Get a unique id
        Return uuid unique id
        """
        return uuid.uuid4()

    @staticmethod
    def file_hash(algo, filename):
        """
        Hash a file with given algorithm
        [sha256, md5]
        Return string hash
        """
        if(algo == 'sha256'):
            return utils.file_hash_sha256(filename)
        elif(algo == 'md5'):
            return utils.file_hash_md5(filename)

        raise ValueError('Algorithm {} not implemented.'.format(algo))

    @staticmethod
    def file_hash_sha256(filename):
        """
        Get the file SHA256
        Return string hash
        """
        h = hashlib.sha256()
        with open(filename, 'rb', buffering=0) as f:
            for b in iter(lambda: f.read(128*1024), b''):
                h.update(b)
        return h.hexdigest()

    @staticmethod
    def file_hash_md5(filename):
        """
        Get the file MD5
        Return string hash
        """
        hash_md5 = hashlib.md5()
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    @staticmethod
    def file_get_contents(filename, mode='r'):
        """
        Get the content of a file
        Return string content
        """
        content = ''
        if os.path.exists(filename):
            fp = open(filename, mode)
            content = fp.read()
            fp.close()
        return content

    @staticmethod
    def file_put_contents(filename, contents):
        """
        Write content to a file
        """
        file = open(filename, 'w')
        file.write(contents)
        file.close()

    @staticmethod
    def file_get_json(filename):
        """
        Load a json object from file
        Return collection json
        """
        if os.path.exists(filename):
            if(utils.check_mime_type(filename, ['application/json', 'text/plain'])):
                content = utils.file_get_contents(filename)
                return json.loads(content)
            else:
                raise ValueError(
                    '{} is not a valid json file.'.format(filename))

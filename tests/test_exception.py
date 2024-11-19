#!/usr/bin/env python3

import unittest
import fdroidserver


class ExceptionTest(unittest.TestCase):
    '''fdroidserver/exception.py'''

    def test_FDroidException(self):
        try:
            raise fdroidserver.exception.FDroidException()
        except fdroidserver.exception.FDroidException as e:
            str(e)

        try:
            raise fdroidserver.exception.FDroidException(9)
        except fdroidserver.exception.FDroidException as e:
            str(e)

        try:
            raise fdroidserver.exception.FDroidException(-123.12234)
        except fdroidserver.exception.FDroidException as e:
            str(e)

        try:
            raise fdroidserver.exception.FDroidException("this is a string")
        except fdroidserver.exception.FDroidException as e:
            str(e)

        try:
            raise fdroidserver.exception.FDroidException(['one', 'two', 'three'])
        except fdroidserver.exception.FDroidException as e:
            str(e)

        try:
            raise fdroidserver.exception.FDroidException(('one', 'two', 'three'))
        except fdroidserver.exception.FDroidException as e:
            str(e)

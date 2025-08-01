#!/usr/bin/env python3

import hashlib
import os
import sys
import unittest
from tempfile import TemporaryDirectory

from fdroidserver import common, signatures

from .shared_test_code import TmpCwd

basedir = os.path.dirname(__file__)


class SignaturesTest(unittest.TestCase):
    def setUp(self):
        common.config = None
        config = common.read_config()
        config['jarsigner'] = common.find_sdk_tools_cmd('jarsigner')
        common.config = config

    @unittest.skipIf(sys.byteorder == 'big', "androguard is not ported to big-endian")
    def test_main(self):
        class OptionsFixture:
            APK = [os.path.join(basedir, 'repo', 'com.politedroid_3.apk')]

        with TemporaryDirectory() as tmpdir, TmpCwd(tmpdir):
            signatures.extract(OptionsFixture)

            # check if extracted signatures are where they are supposed to be
            # also verify weather if extracted file contain what they should
            filesAndHashes = (
                (
                    os.path.join(
                        'metadata', 'com.politedroid', 'signatures', '3', 'MANIFEST.MF'
                    ),
                    '7dcd83f0c41a75457fd2311bf3c4578f80d684362d74ba8dc52838d353f31cf2',
                ),
                (
                    os.path.join(
                        'metadata', 'com.politedroid', 'signatures', '3', 'RELEASE.RSA'
                    ),
                    '883ef3d5a6e0bf69d2a58d9e255a7930f08a49abc38e216ed054943c99c8fdb4',
                ),
                (
                    os.path.join(
                        'metadata', 'com.politedroid', 'signatures', '3', 'RELEASE.SF'
                    ),
                    '99fbb3211ef5d7c1253f3a7ad4836eadc9905103ce6a75916c40de2831958284',
                ),
            )
            for path, checksum in filesAndHashes:
                self.assertTrue(
                    os.path.isfile(path),
                    f'check whether {path!r} was extracted correctly.',
                )
                with open(path, 'rb') as f:
                    self.assertEqual(hashlib.sha256(f.read()).hexdigest(), checksum)

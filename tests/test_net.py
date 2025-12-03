#!/usr/bin/env python3

import os
import random
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

from fdroidserver import net


class RetryServer:
    """A stupid simple HTTP server that can fail to connect.

    Proxy settings via environment variables can interfere with this
    test. The requests library will automatically pick up proxy
    settings from environment variables. Proxy settings can force the
    local connection over the proxy, which might not support that,
    then this fails with an error like 405 or others.

    """

    def __init__(self, port=None, failures=3):
        self.port = port
        if self.port is None:
            self.port = random.randint(1024, 65535)  # nosec B311
        self.failures = failures
        self.stop_event = threading.Event()
        threading.Thread(target=self.run_fake_server).start()

    def stop(self):
        self.stop_event.set()

    def run_fake_server(self):
        addr = ('localhost', self.port)
        # localhost might not be a valid name for all families, use the first available
        family = socket.getaddrinfo(addr[0], addr[1], type=socket.SOCK_STREAM)[0][0]
        server_sock = socket.create_server(addr, family=family)
        server_sock.listen(5)
        server_sock.settimeout(5)
        time.sleep(0.001)  # wait for it to start

        while not self.stop_event.is_set():
            self.failures -= 1
            conn = None
            try:
                conn, address = server_sock.accept()
                conn.settimeout(5)
            except TimeoutError:
                break
            if self.failures > 0:
                conn.close()
                continue
            conn.recv(8192)  # request ignored
            self.reply = b"""HTTP/1.1 200 OK
                Date: Mon, 26 Feb 2024 09:00:14 GMT
                Connection: close
                Content-Type: text/html

                <HTML><BODY>Hello World!</HEAD></HTML>
                """
            self.reply = self.reply.replace(b'                ', b'')  # dedent
            conn.sendall(self.reply)
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()

            self.stop_event.wait(timeout=1)
        server_sock.shutdown(socket.SHUT_RDWR)
        server_sock.close()


class NetTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        os.chdir(self.tempdir.name)
        Path('tmp').mkdir()

    def tearDown(self):
        self.tempdir.cleanup()

    @patch('requests.Session.get')
    def test_download_file_url_parsing(self, requests_get):
        # pylint: disable=unused-argument
        def _get(url, stream, allow_redirects, headers, timeout):
            return MagicMock()

        requests_get.side_effect = _get
        f = net.download_file('https://f-droid.org/repo/entry.jar', retries=0)
        requests_get.assert_called()
        self.assertTrue(os.path.exists(f))
        self.assertEqual('tmp/entry.jar', f)

        f = net.download_file(
            'https://d-05.example.com/custom/com.downloader.aegis-3175421.apk?_fn=QVBLUHVyZV92My4xNy41NF9hcGtwdXJlLmNvbS5hcGs&_p=Y29tLmFwa3B1cmUuYWVnb24&am=6avvTpfJ1dMl9-K6JYKzQw&arg=downloader%3A%2F%2Fcampaign%2F%3Futm_medium%3Ddownloader%26utm_source%3Daegis&at=1652080635&k=1f6e58465df3a441665e585719ab0b13627a117f&r=https%3A%2F%2Fdownloader.com%2Fdownloader-app.html%3Ficn%3Daegis%26ici%3Dimage_qr&uu=http%3A%2F%2F172.16.82.1%2Fcustom%2Fcom.downloader.aegis-3175421.apk%3Fk%3D3fb9c4ae0be578206f6a1c330736fac1627a117f',
            retries=0,
        )
        self.assertTrue(requests_get.called)
        self.assertTrue(os.path.exists(f))
        self.assertEqual('tmp/com.downloader.aegis-3175421.apk', f)

    @patch.dict(os.environ, clear=True)
    def test_download_file_no_http(self):
        with self.assertRaises(requests.exceptions.InvalidSchema):
            net.download_file('http://neverssl.com/repo/entry.jar')

    @patch.dict(os.environ, clear=True)
    def test_download_file_no_git(self):
        with self.assertRaises(requests.exceptions.InvalidSchema):
            net.download_file('git://github.com/')

    @patch.dict(os.environ, clear=True)
    def test_download_file_retries(self):
        server = RetryServer()
        f = net.download_file(f'http://localhost:{server.port}/f.txt', https_only=False)
        # strip the HTTP headers and compare the reply
        self.assertEqual(server.reply.split(b'\n\n')[1], Path(f).read_bytes())
        server.stop()

    @patch.dict(os.environ, clear=True)
    def test_download_file_retries_not_forever(self):
        """The retry logic should eventually exit with an error."""
        server = RetryServer(failures=5)
        with self.assertRaises(requests.exceptions.ConnectionError):
            net.download_file(f'http://localhost:{server.port}/f.txt', https_only=False)
        server.stop()

    @unittest.skipIf(os.getenv('CI'), 'FIXME this fails mysteriously only in GitLab CI')
    @patch.dict(os.environ, clear=True)
    def test_download_using_mirrors_retries(self):
        server = RetryServer()
        f = net.download_using_mirrors(
            [
                'https://fake.com/f.txt',  # 404 or 301 Redirect
                'https://httpbin.org/status/403',
                'https://httpbin.org/status/500',
                'http://localhost:1/f.txt',  # ConnectionError
                'http://localhost:%d/should-succeed' % server.port,
            ],
        )
        # strip the HTTP headers and compare the reply
        self.assertEqual(server.reply.split(b'\n\n')[1], Path(f).read_bytes())
        server.stop()

    @patch.dict(os.environ, clear=True)
    def test_download_using_mirrors_retries_not_forever(self):
        """The retry logic should eventually exit with an error."""
        server = RetryServer(failures=5)
        with self.assertRaises(requests.exceptions.ConnectionError):
            net.download_using_mirrors(['http://localhost:%d/' % server.port])
        server.stop()

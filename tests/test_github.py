#!/usr/bin/env python3

import unittest
import unittest.mock

from .testcommon import mock_urlopen
import fdroidserver


class GithubApiTest(unittest.TestCase):
    def test__init(self):
        api = fdroidserver.github.GithubApi('faketoken', 'fakerepopath')
        self.assertEqual(api._api_token, 'faketoken')
        self.assertEqual(api._repo_path, 'fakerepopath')

    def test__req(self):
        api = fdroidserver.github.GithubApi('faketoken', 'fakerepopath')
        r = api._req('https://fakeurl', data='fakedata')
        self.assertEqual(r.full_url, 'https://fakeurl')
        self.assertEqual(r.data, "fakedata")
        self.assertDictEqual(
            r.headers,
            {
                'Accept': 'application/vnd.github+json',
                'Authorization': 'Bearer faketoken',
                'X-github-api-version': '2022-11-28',
            },
        )

    def test_list_released_tags(self):
        api = fdroidserver.github.GithubApi('faketoken', 'fakerepopath')
        uomock = mock_urlopen(
            body='[{"tag_name": "fake"}, {"tag_name": "double_fake"}]'
        )
        with unittest.mock.patch("urllib.request.urlopen", uomock):
            result = api.list_released_tags()
        self.assertListEqual(result, ['fake', 'double_fake'])

    def test_list_unreleased_tags(self):
        api = fdroidserver.github.GithubApi('faketoken', 'fakerepopath')

        api.list_all_tags = unittest.mock.Mock(return_value=[1, 2, 3, 4])
        api.list_released_tags = unittest.mock.Mock(return_value=[1, 2])

        result = api.list_unreleased_tags()

        self.assertListEqual(result, [3, 4])

    def test_tag_exists(self):
        api = fdroidserver.github.GithubApi('faketoken', 'fakerepopath')
        uomock = mock_urlopen(body='[{"ref": "refs/tags/fake_tag"}]')
        with unittest.mock.patch("urllib.request.urlopen", uomock):
            result = api.tag_exists('fake_tag')
        self.assertTrue(result)

    def test_tag_exists_failure(self):
        api = fdroidserver.github.GithubApi('faketoken', 'fakerepopath')

        uomock = mock_urlopen(body='[{"error": "failure"}]')

        with unittest.mock.patch("urllib.request.urlopen", uomock):
            success = api.tag_exists('fake_tag')

        self.assertFalse(success)

    def test_list_all_tags(self):
        api = fdroidserver.github.GithubApi('faketoken', 'fakerepopath')

        uomock = mock_urlopen(
            body='[{"ref": "refs/tags/fake"}, {"ref": "refs/tags/double_fake"}]'
        )

        with unittest.mock.patch("urllib.request.urlopen", uomock):
            result = api.list_all_tags()

        self.assertListEqual(result, ['fake', 'double_fake'])

    def test_create_release(self):
        api = fdroidserver.github.GithubApi('faketoken', 'fakerepopath')

        uomock = mock_urlopen(body='{"id": "fakeid"}')
        api.tag_exists = lambda x: True
        api._create_release_asset = unittest.mock.Mock()

        with unittest.mock.patch("urllib.request.urlopen", uomock):
            success = api.create_release('faketag', ['file_a', 'file_b'], body="bdy")
        self.assertTrue(success)

        req = uomock.call_args_list[0][0][0]
        self.assertEqual(1, len(uomock.call_args_list))
        self.assertEqual(2, len(uomock.call_args_list[0]))
        self.assertEqual(1, len(uomock.call_args_list[0][0]))
        self.assertEqual(
            req.full_url,
            'https://api.github.com/repos/fakerepopath/releases',
        )
        self.assertEqual(req.data, b'{"tag_name": "faketag", "body": "bdy"}')
        self.assertListEqual(
            api._create_release_asset.call_args_list,
            [
                unittest.mock.call('fakeid', 'file_a'),
                unittest.mock.call('fakeid', 'file_b'),
            ],
        )

    def test__create_release_asset(self):
        api = fdroidserver.github.GithubApi('faketoken', 'fakerepopath')
        uomock = mock_urlopen()

        with unittest.mock.patch(
            'fdroidserver.github.open',
            unittest.mock.mock_open(read_data=b"fake_content"),
        ), unittest.mock.patch("urllib.request.urlopen", uomock):
            success = api._create_release_asset('fake_id', 'fake_file')

        self.assertTrue(success)

        req = uomock.call_args_list[0][0][0]
        self.assertEqual(1, len(uomock.call_args_list))
        self.assertEqual(2, len(uomock.call_args_list[0]))
        self.assertEqual(1, len(uomock.call_args_list[0][0]))
        self.assertEqual(
            req.full_url,
            'https://uploads.github.com/repos/fakerepopath/releases/fake_id/assets?name=fake_file',
        )
        self.assertDictEqual(
            req.headers,
            {
                "Accept": "application/vnd.github+json",
                'Authorization': 'Bearer faketoken',
                'Content-type': 'application/octet-stream',
                'X-github-api-version': '2022-11-28',
            },
        )
        self.assertEqual(req.data, b'fake_content')

#!/usr/bin/env python3
#
# github.py - part of the FDroid server tools
# Copyright (C) 2024, Michael Pöhn, michael@poehn.at
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json
import pathlib
import urllib.request
import urllib.parse


class GithubApi:
    """Wrapper for some select calls to GitHub Json/REST API.

    This class wraps some calls to api.github.com. This is not intended to be a
    general API wrapper. Instead it's purpose is to return pre-filtered and
    transformed data that's playing well with other fdroidserver functions.

    With the GitHub API, the token is optional, but it has pretty
    severe rate limiting.

    """

    def __init__(self, api_token, repo_path):
        self._api_token = api_token
        if repo_path.startswith("https://github.com/"):
            self._repo_path = repo_path[19:]
        else:
            self._repo_path = repo_path

    def _req(self, url, data=None):
        h = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._api_token:
            h["Authorization"] = f"Bearer {self._api_token}"
        return urllib.request.Request(
            url,
            headers=h,
            data=data,
        )

    def list_released_tags(self):
        """List of all tags that are associated with a release for this repo on GitHub."""
        names = []
        req = self._req(f"https://api.github.com/repos/{self._repo_path}/releases")
        with urllib.request.urlopen(req) as resp:  # nosec CWE-22 disable bandit warning
            releases = json.load(resp)
            for release in releases:
                names.append(release['tag_name'])
        return names

    def list_unreleased_tags(self):
        all_tags = self.list_all_tags()
        released_tags = self.list_released_tags()
        return [x for x in all_tags if x not in released_tags]

    def get_latest_apk(self):
        req = self._req(
            f"https://api.github.com/repos/{self._repo_path}/releases/latest"
        )
        with urllib.request.urlopen(req) as resp:  # nosec CWE-22 disable bandit warning
            assets = json.load(resp)['assets']
            for asset in assets:
                url = asset.get('browser_download_url')
                if url and url.endswith('.apk'):
                    return url

    def tag_exists(self, tag):
        """
        Check if git tag is present on github.

        https://docs.github.com/en/rest/git/refs?apiVersion=2022-11-28#list-matching-references--fine-grained-access-tokens
        """
        req = self._req(
            f"https://api.github.com/repos/{self._repo_path}/git/matching-refs/tags/{tag}"
        )
        with urllib.request.urlopen(req) as resp:  # nosec CWE-22 disable bandit warning
            rd = json.load(resp)
            return len(rd) == 1 and rd[0].get("ref", False) == f"refs/tags/{tag}"
        return False

    def list_all_tags(self):
        """Get list of all tags for this repo on GitHub."""
        tags = []
        req = self._req(
            f"https://api.github.com/repos/{self._repo_path}/git/matching-refs/tags/"
        )
        with urllib.request.urlopen(req) as resp:  # nosec CWE-22 disable bandit warning
            refs = json.load(resp)
            for ref in refs:
                r = ref.get('ref', '')
                if r.startswith('refs/tags/'):
                    tags.append(r[10:])
        return tags

    def create_release(self, tag, files, body=''):
        """
        Create a new release on github.

        also see: https://docs.github.com/en/rest/releases/releases?apiVersion=2022-11-28#create-a-release

        :returns: True if release was created, False if release already exists
        :raises: urllib exceptions in case of network or api errors, also
                 raises an exception when the tag doesn't exists.
        """
        # Querying github to create a new release for a non-existent tag, will
        # also create that tag on github. So we need an additional check to
        # prevent this behavior.
        if not self.tag_exists(tag):
            raise Exception(
                f"can't create github release for {self._repo_path} {tag}, tag doesn't exists"
            )
        # create the relase on github
        req = self._req(
            f"https://api.github.com/repos/{self._repo_path}/releases",
            data=json.dumps(
                {
                    "tag_name": tag,
                    "body": body,
                }
            ).encode("utf-8"),
        )
        try:
            with urllib.request.urlopen(  # nosec CWE-22 disable bandit warning
                req
            ) as resp:
                release_id = json.load(resp)['id']
        except urllib.error.HTTPError as e:
            if e.status == 422:
                codes = [x['code'] for x in json.load(e).get('errors', [])]
                if "already_exists" in codes:
                    return False
            raise e

        # attach / upload all files for the relase
        for file in files:
            self._create_release_asset(release_id, file)

        return True

    def _create_release_asset(self, release_id, file):
        """
        Attach a file to a release on GitHub.

        This uploads a file to github relases, it will be attached to the supplied release

        also see: https://docs.github.com/en/rest/releases/assets?apiVersion=2022-11-28#upload-a-release-asset
        """
        file = pathlib.Path(file)
        with open(file, 'rb') as f:
            req = urllib.request.Request(
                f"https://uploads.github.com/repos/{self._repo_path}/releases/{release_id}/assets?name={file.name}",
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {self._api_token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "Content-Type": "application/octet-stream",
                },
                data=f.read(),
            )
            with urllib.request.urlopen(req):  # nosec CWE-22 disable bandit warning
                return True
            return False

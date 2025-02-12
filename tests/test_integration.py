import itertools
import os
import re
import shlex
import shutil
import subprocess
import threading
import unittest
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ruamel.yaml import YAML

try:
    from androguard.core.bytecodes.apk import get_apkid  # androguard <4
except ModuleNotFoundError:
    from androguard.core.apk import get_apkid

# TODO: port generic tests that use index.xml to index-v2 (test that
#       explicitly test index-v0 should still use index.xml)


basedir = Path(__file__).parent
FILES = basedir

try:
    WORKSPACE = Path(os.environ["WORKSPACE"])
except KeyError:
    WORKSPACE = basedir.parent

from fdroidserver import common

conf = {"sdk_path": os.getenv("ANDROID_HOME", "")}
common.find_apksigner(conf)
USE_APKSIGNER = "apksigner" in conf


class IntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.fdroid_cmd = shlex.split(os.environ["fdroid"])
        except KeyError:
            cls.fdroid_cmd = [WORKSPACE / "fdroid"]

        cls.tmp = WORKSPACE / ".testfiles"
        cls.tmp_repo = cls.tmp / "repo"

        os.environ.update(
            {
                "GIT_AUTHOR_NAME": "Test",
                "GIT_AUTHOR_EMAIL": "no@mail",
                "GIT_COMMITTER_NAME": "Test",
                "GIT_COMMITTER_EMAIL": "no@mail",
                "GIT_ALLOW_PROTOCOL": "file:https",
            }
        )

    def setUp(self):
        self.prev_cwd = Path()
        self.tmp_repo.mkdir(parents=True)
        os.chdir(self.tmp_repo)

    def tearDown(self):
        os.chdir(self.prev_cwd)
        shutil.rmtree(self.tmp)

    def assert_run(self, *args, **kwargs):
        proc = subprocess.run(*args, **kwargs)
        self.assertEqual(proc.returncode, 0)
        return proc

    def assert_run_fail(self, *args, **kwargs):
        proc = subprocess.run(*args, **kwargs)
        self.assertNotEqual(proc.returncode, 0)
        return proc

    @staticmethod
    def update_yaml(path, items, replace=False):
        """Update a .yml file, e.g. config.yml, with the given items."""
        yaml = YAML()
        doc = {}
        if not replace:
            try:
                with open(path) as f:
                    doc = yaml.load(f)
            except FileNotFoundError:
                pass
        doc.update(items)
        with open(path, "w") as f:
            yaml.dump(doc, f)

    @staticmethod
    def remove_lines(path, unwanted_strings):
        """Remove the lines in the path that contain the unwanted strings."""

        def contains_unwanted(line, unwanted_strings):
            for str in unwanted_strings:
                if str in line:
                    return True
            return False

        with open(path) as f:
            filtered = [
                line for line in f if not contains_unwanted(line, unwanted_strings)
            ]

        with open(path, "w") as f:
            for line in filtered:
                f.write(line)

    @staticmethod
    def copy_apks_into_repo():
        def to_skip(name):
            for str in [
                "unaligned",
                "unsigned",
                "badsig",
                "badcert",
                "bad-unicode",
                "janus.apk",
            ]:
                if str in name:
                    return True
            return False

        for f in FILES.glob("*.apk"):
            if not to_skip(f.name):
                appid, versionCode, _ignored = get_apkid(f)
                shutil.copy(
                    f,
                    Path("repo") / common.get_release_apk_filename(appid, versionCode),
                )

    @staticmethod
    def create_fake_android_home(path):
        (path / "tools").mkdir()
        (path / "platform-tools").mkdir()
        (path / "build-tools/34.0.0").mkdir(parents=True)
        (path / "build-tools/34.0.0/aapt").touch()

    def fdroid_init_with_prebuilt_keystore(self, keystore_path=FILES / "keystore.jks"):
        self.assert_run(
            self.fdroid_cmd
            + ["init", "--keystore", keystore_path, "--repo-keyalias", "sova"]
        )
        self.update_yaml(
            "config.yml",
            {
                "keystorepass": "r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI=",
                "keypass": "r9aquRHYoI8+dYz6jKrLntQ5/NJNASFBacJh7Jv2BlI=",
            },
        )

    @unittest.skipUnless(USE_APKSIGNER, "requires apksigner")
    def test_run_process_when_building_and_signing_are_on_separate_machines(self):
        shutil.copy(FILES / "keystore.jks", "keystore.jks")
        self.fdroid_init_with_prebuilt_keystore("keystore.jks")
        self.update_yaml(
            "config.yml",
            {
                "make_current_version_link": True,
                "keydname": "CN=Birdman, OU=Cell, O=Alcatraz, L=Alcatraz, S=California, C=US",
            },
        )

        Path("metadata").mkdir()
        shutil.copy(FILES / "metadata/info.guardianproject.urzip.yml", "metadata")
        Path("unsigned").mkdir()
        shutil.copy(
            FILES / "urzip-release-unsigned.apk",
            "unsigned/info.guardianproject.urzip_100.apk",
        )

        self.assert_run(self.fdroid_cmd + ["publish", "--verbose"])
        self.assert_run(self.fdroid_cmd + ["update", "--verbose", "--nosign"])
        self.assert_run(self.fdroid_cmd + ["signindex", "--verbose"])

        self.assertIn(
            '<application id="info.guardianproject.urzip">',
            Path("repo/index.xml").read_text(),
        )
        self.assertTrue(Path("repo/index.jar").is_file())
        self.assertTrue(Path("repo/index-v1.jar").is_file())
        apkcache = Path("tmp/apkcache.json")
        self.assertTrue(apkcache.is_file())
        self.assertTrue(apkcache.stat().st_size > 0)
        self.assertTrue(Path("urzip.apk").is_symlink())

    def test_utf8_metadata(self):
        self.fdroid_init_with_prebuilt_keystore()
        self.update_yaml(
            "config.yml",
            {
                "repo_description": "获取已安装在您的设备上的应用的",
                "mirrors": ["https://foo.bar/fdroid", "http://secret.onion/fdroid"],
            },
        )
        shutil.copy(FILES / "urzip.apk", "repo")
        shutil.copy(FILES / "bad-unicode-πÇÇ现代通用字-български-عربي1.apk", "repo")
        Path("metadata").mkdir()
        shutil.copy(FILES / "metadata/info.guardianproject.urzip.yml", "metadata")

        self.assert_run(self.fdroid_cmd + ["readmeta"])
        self.assert_run(self.fdroid_cmd + ["update"])

    def test_copy_git_import_and_run_fdroid_scanner_on_it(self):
        url = "https://gitlab.com/fdroid/ci-test-app.git"
        Path("metadata").mkdir()
        self.update_yaml(
            "metadata/org.fdroid.ci.test.app.yml",
            {
                "AutoName": "Just A Test",
                "WebSite": None,
                "Builds": [
                    {
                        "versionName": "0.3",
                        "versionCode": 300,
                        "commit": "0.3",
                        "subdir": "app",
                        "gradle": ["yes"],
                    }
                ],
                "Repo": url,
                "RepoType": "git",
            },
        )

        self.assert_run(["git", "clone", url, "build/org.fdroid.ci.test.app"])
        self.assert_run(
            self.fdroid_cmd + ["scanner", "org.fdroid.ci.test.app", "--verbose"]
        )

    def test_copy_repo_generate_java_gpg_keys_update_and_gpgsign(self):
        self.fdroid_init_with_prebuilt_keystore()
        shutil.copytree(FILES / "repo", "repo", dirs_exist_ok=True)
        for dir in ["config", "metadata", "gnupghome"]:
            shutil.copytree(FILES / dir, dir)
        gnupghome = Path("gnupghome").resolve()
        os.chmod(gnupghome, 0o700)
        self.update_yaml(
            "config.yml",
            {
                "install_list": "org.adaway",
                "uninstall_list": ["com.android.vending", "com.facebook.orca"],
                "gpghome": str(gnupghome),
                "gpgkey": "CE71F7FB",
                "mirrors": [
                    "http://foobarfoobarfoobar.onion/fdroid",
                    "https://foo.bar/fdroid",
                ],
            },
        )
        self.assert_run(
            self.fdroid_cmd + ["update", "--verbose", "--pretty"],
            env=os.environ | {"LC_MESSAGES": "C.UTF-8"},
        )
        index_xml = Path("repo/index.xml").read_text()
        self.assertIn("<application id=", index_xml)
        self.assertIn("<install packageName=", index_xml)
        self.assertIn("<uninstall packageName=", index_xml)
        self.assertTrue(Path("repo/index.jar").is_file())
        self.assertTrue(Path("repo/index-v1.jar").is_file())

        self.assert_run(self.fdroid_cmd + ["gpgsign", "--verbose"])

        self.assertTrue(Path("repo/obb.mainpatch.current_1619.apk.asc").is_file())
        self.assertTrue(
            Path("repo/obb.main.twoversions_1101617_src.tar.gz.asc").is_file()
        )
        self.assertFalse(Path("repo/obb.mainpatch.current_1619.apk.asc.asc").exists())
        self.assertFalse(
            Path("repo/obb.main.twoversions_1101617_src.tar.gz.asc.asc").exists()
        )
        self.assertFalse(Path("repo/index.xml.asc").exists())

        index_v1_json = Path("repo/index-v1.json").read_text()
        v0_timestamp = re.search(r'timestamp="(\d+)"', index_xml).group(1)
        v1_timestamp = re.search(r'"timestamp": (\d+)', index_v1_json).group(1)[:-3]
        self.assertEqual(v0_timestamp, v1_timestamp)

        # we can't easily reproduce the timestamps for things, so just hardcode them
        index_xml = re.sub(r'timestamp="\d+"', 'timestamp="1676634233"', index_xml)
        self.assertEqual((FILES / "repo/index.xml").read_text(), index_xml)
        index_v1_json = re.sub(
            r'"timestamp": (\d+)', '"timestamp": 1676634233000', index_v1_json
        )
        self.assertEqual((FILES / "repo/index-v1.json").read_text(), index_v1_json)

        expected_index_v2_json = (FILES / "repo/index-v2.json").read_text()
        expected_index_v2_json = re.sub(
            r',\s*"ipfsCIDv1":\s*"[\w]+"', "", expected_index_v2_json
        )

        index_v2_json = Path("repo/index-v2.json").read_text()
        index_v2_json = re.sub(
            r'"timestamp": (\d+)', '"timestamp": 1676634233000', index_v2_json
        )
        index_v2_json = re.sub(r',\s*"ipfsCIDv1":\s*"[\w]+"', "", index_v2_json)
        self.assertEqual(index_v2_json, expected_index_v2_json)

    def test_moving_lots_of_apks_to_the_archive(self):
        self.fdroid_init_with_prebuilt_keystore()
        Path("metadata").mkdir()
        for path in (FILES / "metadata").glob("*.yml"):
            shutil.copy(path, "metadata")
        self.update_yaml(
            "metadata/info.guardianproject.urzip.yml",
            {"Summary": "good test version of urzip"},
            replace=True,
        )
        self.update_yaml(
            "metadata/org.bitbucket.tickytacky.mirrormirror.yml",
            {"Summary": "good MD5 sig, which is disabled algorithm"},
            replace=True,
        )
        for f in Path("metadata").glob("*.yml"):
            self.remove_lines(f, ["ArchivePolicy:"])
        for f in itertools.chain(
            FILES.glob("urzip.apk"),
            FILES.glob("org.bitbucket.tickytacky.mirrormirror_[0-9].apk"),
            FILES.glob("repo/com.politedroid_[0-9].apk"),
            FILES.glob("repo/obb.main.twoversions_110161[357].apk"),
        ):
            shutil.copy(f, "repo")
        self.update_yaml("config.yml", {"archive_older": 3})

        self.assert_run(self.fdroid_cmd + ["update", "--pretty", "--nosign"])
        with open("archive/index.xml") as f:
            archive_cnt = sum(1 for line in f if "<package>" in line)
        with open("repo/index.xml") as f:
            repo_cnt = sum(1 for line in f if "<package>" in line)
        if USE_APKSIGNER:
            self.assertEqual(archive_cnt, 2)
            self.assertEqual(repo_cnt, 10)
        else:
            # This will fail when jarsigner allows MD5 for APK signatures
            self.assertEqual(archive_cnt, 5)
            self.assertEqual(repo_cnt, 7)

    @unittest.skipIf(USE_APKSIGNER, "runs only without apksigner")
    def test_per_app_archive_policy(self):
        self.fdroid_init_with_prebuilt_keystore()
        Path("metadata").mkdir()
        shutil.copy(FILES / "metadata/com.politedroid.yml", "metadata")
        for f in FILES.glob("repo/com.politedroid_[0-9].apk"):
            shutil.copy(f, "repo")
        self.update_yaml("config.yml", {"archive_older": 3})

        self.assert_run(self.fdroid_cmd + ["update", "--pretty", "--nosign"])
        repo = Path("repo/index.xml").read_text()
        repo_cnt = sum(1 for line in repo.splitlines() if "<package>" in line)
        archive = Path("archive/index.xml").read_text()
        archive_cnt = sum(1 for line in archive.splitlines() if "<package>" in line)
        self.assertEqual(repo_cnt, 4)
        self.assertEqual(archive_cnt, 0)
        self.assertIn("com.politedroid_3.apk", repo)
        self.assertIn("com.politedroid_4.apk", repo)
        self.assertIn("com.politedroid_5.apk", repo)
        self.assertIn("com.politedroid_6.apk", repo)
        self.assertTrue(Path("repo/com.politedroid_3.apk").is_file())
        self.assertTrue(Path("repo/com.politedroid_4.apk").is_file())
        self.assertTrue(Path("repo/com.politedroid_5.apk").is_file())
        self.assertTrue(Path("repo/com.politedroid_6.apk").is_file())

        # enable one app in the repo
        self.update_yaml("metadata/com.politedroid.yml", {"ArchivePolicy": 1})
        self.assert_run(self.fdroid_cmd + ["update", "--pretty", "--nosign"])
        repo = Path("repo/index.xml").read_text()
        repo_cnt = sum(1 for line in repo.splitlines() if "<package>" in line)
        archive = Path("archive/index.xml").read_text()
        archive_cnt = sum(1 for line in archive.splitlines() if "<package>" in line)
        self.assertEqual(repo_cnt, 1)
        self.assertEqual(archive_cnt, 3)
        self.assertIn("com.politedroid_6.apk", repo)
        self.assertIn("com.politedroid_3.apk", archive)
        self.assertIn("com.politedroid_4.apk", archive)
        self.assertIn("com.politedroid_5.apk", archive)
        self.assertTrue(Path("repo/com.politedroid_6.apk").is_file())
        self.assertTrue(Path("archive/com.politedroid_3.apk").is_file())
        self.assertTrue(Path("archive/com.politedroid_4.apk").is_file())
        self.assertTrue(Path("archive/com.politedroid_5.apk").is_file())

        # remove all apps from the repo
        self.update_yaml("metadata/com.politedroid.yml", {"ArchivePolicy": 0})
        self.assert_run(self.fdroid_cmd + ["update", "--pretty", "--nosign"])
        repo = Path("repo/index.xml").read_text()
        repo_cnt = sum(1 for line in repo.splitlines() if "<package>" in line)
        archive = Path("archive/index.xml").read_text()
        archive_cnt = sum(1 for line in archive.splitlines() if "<package>" in line)
        self.assertEqual(repo_cnt, 0)
        self.assertEqual(archive_cnt, 4)
        self.assertIn("com.politedroid_3.apk", archive)
        self.assertIn("com.politedroid_4.apk", archive)
        self.assertIn("com.politedroid_5.apk", archive)
        self.assertIn("com.politedroid_6.apk", archive)
        self.assertTrue(Path("archive/com.politedroid_3.apk").is_file())
        self.assertTrue(Path("archive/com.politedroid_4.apk").is_file())
        self.assertTrue(Path("archive/com.politedroid_5.apk").is_file())
        self.assertTrue(Path("archive/com.politedroid_6.apk").is_file())
        self.assertFalse(Path("repo/com.politedroid_6.apk").exists())

        # move back one from archive to the repo
        self.update_yaml("metadata/com.politedroid.yml", {"ArchivePolicy": 1})
        self.assert_run(self.fdroid_cmd + ["update", "--pretty", "--nosign"])
        repo = Path("repo/index.xml").read_text()
        repo_cnt = sum(1 for line in repo.splitlines() if "<package>" in line)
        archive = Path("archive/index.xml").read_text()
        archive_cnt = sum(1 for line in archive.splitlines() if "<package>" in line)
        self.assertEqual(repo_cnt, 1)
        self.assertEqual(archive_cnt, 3)
        self.assertIn("com.politedroid_6.apk", repo)
        self.assertIn("com.politedroid_3.apk", archive)
        self.assertIn("com.politedroid_4.apk", archive)
        self.assertIn("com.politedroid_5.apk", archive)
        self.assertTrue(Path("repo/com.politedroid_6.apk").is_file())
        self.assertTrue(Path("archive/com.politedroid_3.apk").is_file())
        self.assertTrue(Path("archive/com.politedroid_4.apk").is_file())
        self.assertTrue(Path("archive/com.politedroid_5.apk").is_file())
        self.assertFalse(Path("archive/com.politedroid_6.apk").exists())

        # set an earlier version as CVC and test that it's the only one not archived
        self.update_yaml("metadata/com.politedroid.yml", {"CurrentVersionCode": 5})
        self.assert_run(self.fdroid_cmd + ["update", "--pretty", "--nosign"])
        repo = Path("repo/index.xml").read_text()
        repo_cnt = sum(1 for line in repo.splitlines() if "<package>" in line)
        archive = Path("archive/index.xml").read_text()
        archive_cnt = sum(1 for line in archive.splitlines() if "<package>" in line)
        self.assertEqual(repo_cnt, 1)
        self.assertEqual(archive_cnt, 3)
        self.assertIn("com.politedroid_5.apk", repo)
        self.assertIn("com.politedroid_3.apk", archive)
        self.assertIn("com.politedroid_4.apk", archive)
        self.assertIn("com.politedroid_6.apk", archive)
        self.assertTrue(Path("repo/com.politedroid_5.apk").is_file())
        self.assertFalse(Path("repo/com.politedroid_6.apk").exists())
        self.assertTrue(Path("archive/com.politedroid_3.apk").is_file())
        self.assertTrue(Path("archive/com.politedroid_4.apk").is_file())
        self.assertTrue(Path("archive/com.politedroid_6.apk").is_file())

    def test_moving_old_apks_to_and_from_the_archive(self):
        self.fdroid_init_with_prebuilt_keystore()
        Path("metadata").mkdir()
        shutil.copy(FILES / "metadata/com.politedroid.yml", "metadata")
        self.remove_lines("metadata/com.politedroid.yml", ["ArchivePolicy:"])
        for f in FILES.glob("repo/com.politedroid_[0-9].apk"):
            shutil.copy(f, "repo")
        self.update_yaml("config.yml", {"archive_older": 3})

        self.assert_run(self.fdroid_cmd + ["update", "--pretty", "--nosign"])
        repo = Path("repo/index.xml").read_text()
        repo_cnt = sum(1 for line in repo.splitlines() if "<package>" in line)
        self.assertEqual(repo_cnt, 3)
        self.assertIn("com.politedroid_4.apk", repo)
        self.assertIn("com.politedroid_5.apk", repo)
        self.assertIn("com.politedroid_6.apk", repo)
        self.assertTrue(Path("repo/com.politedroid_4.apk").is_file())
        self.assertTrue(Path("repo/com.politedroid_5.apk").is_file())
        self.assertTrue(Path("repo/com.politedroid_6.apk").is_file())
        archive = Path("archive/index.xml").read_text()
        archive_cnt = sum(1 for line in archive.splitlines() if "<package>" in line)
        self.assertEqual(archive_cnt, 1)
        self.assertIn("com.politedroid_3.apk", archive)
        self.assertTrue(Path("archive/com.politedroid_3.apk").is_file())

        self.update_yaml("config.yml", {"archive_older": 1})
        self.assert_run(self.fdroid_cmd + ["update", "--pretty", "--nosign"])
        repo = Path("repo/index.xml").read_text()
        repo_cnt = sum(1 for line in repo.splitlines() if "<package>" in line)
        self.assertEqual(repo_cnt, 1)
        self.assertIn("com.politedroid_6.apk", repo)
        self.assertTrue(Path("repo/com.politedroid_6.apk").is_file())
        archive = Path("archive/index.xml").read_text()
        archive_cnt = sum(1 for line in archive.splitlines() if "<package>" in line)
        self.assertEqual(archive_cnt, 3)
        self.assertIn("com.politedroid_3.apk", archive)
        self.assertIn("com.politedroid_4.apk", archive)
        self.assertIn("com.politedroid_5.apk", archive)
        self.assertTrue(Path("archive/com.politedroid_3.apk").is_file())
        self.assertTrue(Path("archive/com.politedroid_4.apk").is_file())
        self.assertTrue(Path("archive/com.politedroid_5.apk").is_file())

        # disabling deletes from the archive
        metadata_path = Path("metadata/com.politedroid.yml")
        metadata = metadata_path.read_text()
        metadata = re.sub(
            "versionCode: 4", "versionCode: 4\n    disable: testing deletion", metadata
        )
        metadata_path.write_text(metadata)
        self.assert_run(self.fdroid_cmd + ["update", "--pretty", "--nosign"])
        repo = Path("repo/index.xml").read_text()
        repo_cnt = sum(1 for line in repo.splitlines() if "<package>" in line)
        self.assertEqual(repo_cnt, 1)
        self.assertIn("com.politedroid_6.apk", repo)
        self.assertTrue(Path("repo/com.politedroid_6.apk").is_file())
        archive = Path("archive/index.xml").read_text()
        archive_cnt = sum(1 for line in archive.splitlines() if "<package>" in line)
        self.assertEqual(archive_cnt, 2)
        self.assertIn("com.politedroid_3.apk", archive)
        self.assertNotIn("com.politedroid_4.apk", archive)
        self.assertIn("com.politedroid_5.apk", archive)
        self.assertTrue(Path("archive/com.politedroid_3.apk").is_file())
        self.assertFalse(Path("archive/com.politedroid_4.apk").exists())
        self.assertTrue(Path("archive/com.politedroid_5.apk").is_file())

        # disabling deletes from the repo, and promotes one from the archive
        metadata = re.sub(
            "versionCode: 6", "versionCode: 6\n    disable: testing deletion", metadata
        )
        metadata_path.write_text(metadata)
        self.assert_run(self.fdroid_cmd + ["update", "--pretty", "--nosign"])
        repo = Path("repo/index.xml").read_text()
        repo_cnt = sum(1 for line in repo.splitlines() if "<package>" in line)
        self.assertEqual(repo_cnt, 1)
        self.assertIn("com.politedroid_5.apk", repo)
        self.assertNotIn("com.politedroid_6.apk", repo)
        self.assertTrue(Path("repo/com.politedroid_5.apk").is_file())
        self.assertFalse(Path("repo/com.politedroid_6.apk").exists())
        archive = Path("archive/index.xml").read_text()
        archive_cnt = sum(1 for line in archive.splitlines() if "<package>" in line)
        self.assertEqual(archive_cnt, 1)
        self.assertIn("com.politedroid_3.apk", archive)
        self.assertTrue(Path("archive/com.politedroid_3.apk").is_file())
        self.assertFalse(Path("archive/com.politedroid_6.apk").exists())

    def test_that_verify_can_succeed_and_fail(self):
        Path("tmp").mkdir()
        Path("unsigned").mkdir()
        shutil.copy(FILES / "repo/com.politedroid_6.apk", "tmp")
        shutil.copy(FILES / "repo/com.politedroid_6.apk", "unsigned")
        self.assert_run(
            self.fdroid_cmd
            + ["verify", "--reuse-remote-apk", "--verbose", "com.politedroid"]
        )
        # force a fail
        shutil.copy(
            FILES / "repo/com.politedroid_5.apk", "unsigned/com.politedroid_6.apk"
        )
        self.assert_run_fail(
            self.fdroid_cmd
            + ["verify", "--reuse-remote-apk", "--verbose", "com.politedroid"]
        )

    def test_allowing_disabled_signatures_in_repo_and_archive(self):
        self.fdroid_init_with_prebuilt_keystore()
        self.update_yaml(
            "config.yml", {"allow_disabled_algorithms": True, "archive_older": 3}
        )
        Path("metadata").mkdir()
        shutil.copy(FILES / "metadata/com.politedroid.yml", "metadata")
        self.update_yaml(
            "metadata/info.guardianproject.urzip.yml",
            {"Summary": "good test version of urzip"},
            replace=True,
        )
        self.update_yaml(
            "metadata/org.bitbucket.tickytacky.mirrormirror.yml",
            {"Summary": "good MD5 sig, disabled algorithm"},
            replace=True,
        )
        for f in Path("metadata").glob("*.yml"):
            self.remove_lines(f, ["ArchivePolicy:"])
        for f in itertools.chain(
            FILES.glob("urzip-badsig.apk"),
            FILES.glob("org.bitbucket.tickytacky.mirrormirror_[0-9].apk"),
            FILES.glob("repo/com.politedroid_[0-9].apk"),
        ):
            shutil.copy(f, "repo")

        self.assert_run(self.fdroid_cmd + ["update", "--pretty", "--nosign"])
        repo = Path("repo/index.xml").read_text()
        repo_cnt = sum(1 for line in repo.splitlines() if "<package>" in line)
        archive = Path("archive/index.xml").read_text()
        archive_cnt = sum(1 for line in archive.splitlines() if "<package>" in line)
        self.assertEqual(repo_cnt, 6)
        self.assertEqual(archive_cnt, 2)
        self.assertIn("com.politedroid_4.apk", repo)
        self.assertIn("com.politedroid_5.apk", repo)
        self.assertIn("com.politedroid_6.apk", repo)
        self.assertIn("com.politedroid_3.apk", archive)
        self.assertIn("org.bitbucket.tickytacky.mirrormirror_2.apk", repo)
        self.assertIn("org.bitbucket.tickytacky.mirrormirror_3.apk", repo)
        self.assertIn("org.bitbucket.tickytacky.mirrormirror_4.apk", repo)
        self.assertIn("org.bitbucket.tickytacky.mirrormirror_1.apk", archive)
        self.assertNotIn("urzip-badsig.apk", repo)
        self.assertNotIn("urzip-badsig.apk", archive)
        self.assertTrue(Path("archive/com.politedroid_3.apk").is_file())
        self.assertTrue(Path("repo/com.politedroid_4.apk").is_file())
        self.assertTrue(Path("repo/com.politedroid_5.apk").is_file())
        self.assertTrue(Path("repo/com.politedroid_6.apk").is_file())
        self.assertTrue(
            Path("archive/org.bitbucket.tickytacky.mirrormirror_1.apk").is_file()
        )
        self.assertTrue(
            Path("repo/org.bitbucket.tickytacky.mirrormirror_2.apk").is_file()
        )
        self.assertTrue(
            Path("repo/org.bitbucket.tickytacky.mirrormirror_3.apk").is_file()
        )
        self.assertTrue(
            Path("repo/org.bitbucket.tickytacky.mirrormirror_4.apk").is_file()
        )
        self.assertTrue(Path("archive/urzip-badsig.apk").is_file())

        if not USE_APKSIGNER:
            self.assert_run(self.fdroid_cmd + ["update", "--pretty", "--nosign"])
            repo = Path("repo/index.xml").read_text()
            repo_cnt = sum(1 for line in repo.splitlines() if "<package>" in line)
            archive = Path("archive/index.xml").read_text()
            archive_cnt = sum(1 for line in archive.splitlines() if "<package>" in line)
            self.assertEqual(repo_cnt, 3)
            self.assertEqual(archive_cnt, 5)
            self.assertIn("com.politedroid_4.apk", repo)
            self.assertIn("com.politedroid_5.apk", repo)
            self.assertIn("com.politedroid_6.apk", repo)
            self.assertNotIn("urzip-badsig.apk", repo)
            self.assertIn("org.bitbucket.tickytacky.mirrormirror_1.apk", archive)
            self.assertIn("org.bitbucket.tickytacky.mirrormirror_2.apk", archive)
            self.assertIn("org.bitbucket.tickytacky.mirrormirror_3.apk", archive)
            self.assertIn("org.bitbucket.tickytacky.mirrormirror_4.apk", archive)
            self.assertIn("com.politedroid_3.apk", archive)
            self.assertNotIn("urzip-badsig.apk", archive)
            self.assertTrue(Path("repo/com.politedroid_4.apk").is_file())
            self.assertTrue(Path("repo/com.politedroid_5.apk").is_file())
            self.assertTrue(Path("repo/com.politedroid_6.apk").is_file())
            self.assertTrue(
                Path("archive/org.bitbucket.tickytacky.mirrormirror_1.apk").is_file()
            )
            self.assertTrue(
                Path("archive/org.bitbucket.tickytacky.mirrormirror_2.apk").is_file()
            )
            self.assertTrue(
                Path("archive/org.bitbucket.tickytacky.mirrormirror_3.apk").is_file()
            )
            self.assertTrue(
                Path("archive/org.bitbucket.tickytacky.mirrormirror_4.apk").is_file()
            )
            self.assertTrue(Path("archive/com.politedroid_3.apk").is_file())
            self.assertTrue(Path("archive/urzip-badsig.apk").is_file())

        # test unarchiving when disabled_algorithms are allowed again
        self.update_yaml("config.yml", {"allow_disabled_algorithms": True})
        self.assert_run(self.fdroid_cmd + ["update", "--pretty", "--nosign"])
        with open("archive/index.xml") as f:
            archive_cnt = sum(1 for line in f if "<package>" in line)
        with open("repo/index.xml") as f:
            repo_cnt = sum(1 for line in f if "<package>" in line)
        self.assertEqual(repo_cnt, 6)
        self.assertEqual(archive_cnt, 2)
        self.assertIn("com.politedroid_4.apk", repo)
        self.assertIn("com.politedroid_5.apk", repo)
        self.assertIn("com.politedroid_6.apk", repo)
        self.assertIn("org.bitbucket.tickytacky.mirrormirror_2.apk", repo)
        self.assertIn("org.bitbucket.tickytacky.mirrormirror_3.apk", repo)
        self.assertIn("org.bitbucket.tickytacky.mirrormirror_4.apk", repo)
        self.assertNotIn("urzip-badsig.apk", repo)
        self.assertIn("com.politedroid_3.apk", archive)
        self.assertIn("org.bitbucket.tickytacky.mirrormirror_1.apk", archive)
        self.assertNotIn("urzip-badsig.apk", archive)
        self.assertTrue(Path("repo/com.politedroid_4.apk").is_file())
        self.assertTrue(Path("repo/com.politedroid_5.apk").is_file())
        self.assertTrue(Path("repo/com.politedroid_6.apk").is_file())
        self.assertTrue(
            Path("repo/org.bitbucket.tickytacky.mirrormirror_2.apk").is_file()
        )
        self.assertTrue(
            Path("repo/org.bitbucket.tickytacky.mirrormirror_3.apk").is_file()
        )
        self.assertTrue(
            Path("repo/org.bitbucket.tickytacky.mirrormirror_4.apk").is_file()
        )
        self.assertTrue(Path("archive/com.politedroid_3.apk").is_file())
        self.assertTrue(
            Path("archive/org.bitbucket.tickytacky.mirrormirror_1.apk").is_file()
        )
        self.assertTrue(Path("archive/urzip-badsig.apk").is_file())

    def test_rename_apks_with_fdroid_update_rename_apks_opt_nosign_opt_for_speed(self):
        self.fdroid_init_with_prebuilt_keystore()
        self.update_yaml(
            "config.yml",
            {
                "keydname": "CN=Birdman, OU=Cell, O=Alcatraz, L=Alcatraz, S=California, C=US"
            },
        )
        Path("metadata").mkdir()
        shutil.copy(FILES / "metadata/info.guardianproject.urzip.yml", "metadata")
        shutil.copy(
            FILES / "urzip.apk",
            "repo/asdfiuhk urzip-πÇÇπÇÇ现代汉语通用字-български-عربي1234 ö.apk",
        )
        self.assert_run(
            self.fdroid_cmd + ["update", "--rename-apks", "--pretty", "--nosign"]
        )
        self.assertTrue(Path("repo/info.guardianproject.urzip_100.apk").is_file())
        index_xml = Path("repo/index.xml").read_text()
        index_v1_json = Path("repo/index-v1.json").read_text()
        self.assertIn("info.guardianproject.urzip_100.apk", index_v1_json)
        self.assertIn("info.guardianproject.urzip_100.apk", index_xml)

        shutil.copy(FILES / "urzip-release.apk", "repo")
        self.assert_run(
            self.fdroid_cmd + ["update", "--rename-apks", "--pretty", "--nosign"]
        )
        self.assertTrue(Path("repo/info.guardianproject.urzip_100.apk").is_file())
        self.assertTrue(
            Path("repo/info.guardianproject.urzip_100_b4964fd.apk").is_file()
        )
        index_xml = Path("repo/index.xml").read_text()
        index_v1_json = Path("repo/index-v1.json").read_text()
        self.assertIn("info.guardianproject.urzip_100.apk", index_v1_json)
        self.assertIn("info.guardianproject.urzip_100.apk", index_xml)
        self.assertIn("info.guardianproject.urzip_100_b4964fd.apk", index_v1_json)
        self.assertNotIn("info.guardianproject.urzip_100_b4964fd.apk", index_xml)

        shutil.copy(FILES / "urzip-release.apk", "repo")
        self.assert_run(
            self.fdroid_cmd + ["update", "--rename-apks", "--pretty", "--nosign"]
        )
        self.assertTrue(Path("repo/info.guardianproject.urzip_100.apk").is_file())
        self.assertTrue(
            Path("repo/info.guardianproject.urzip_100_b4964fd.apk").is_file()
        )
        self.assertTrue(
            Path("duplicates/repo/info.guardianproject.urzip_100_b4964fd.apk").is_file()
        )
        index_xml = Path("repo/index.xml").read_text()
        index_v1_json = Path("repo/index-v1.json").read_text()
        self.assertIn("info.guardianproject.urzip_100.apk", index_v1_json)
        self.assertIn("info.guardianproject.urzip_100.apk", index_xml)
        self.assertIn("info.guardianproject.urzip_100_b4964fd.apk", index_v1_json)
        self.assertNotIn("info.guardianproject.urzip_100_b4964fd.apk", index_xml)

    def test_for_added_date_being_set_correctly_for_repo_and_archive(self):
        self.fdroid_init_with_prebuilt_keystore()
        self.update_yaml("config.yml", {"archive_older": 3})
        Path("metadata").mkdir()
        Path("archive").mkdir()
        Path("stats").mkdir()
        shutil.copy(FILES / "repo/com.politedroid_6.apk", "repo")
        shutil.copy(FILES / "repo/index-v2.json", "repo")
        shutil.copy(FILES / "repo/com.politedroid_5.apk", "archive")
        shutil.copy(FILES / "metadata/com.politedroid.yml", "metadata")

        # TODO: the timestamp of the oldest apk in the file should be used, even
        #       if that doesn't exist anymore
        self.update_yaml("metadata/com.politedroid.yml", {"ArchivePolicy": 1})

        self.assert_run(self.fdroid_cmd + ["update", "--pretty", "--nosign"])
        timestamp = int(datetime(2017, 6, 23, tzinfo=timezone.utc).timestamp()) * 1000
        index_v1_json = Path("repo/index-v1.json").read_text()
        self.assertIn(f'"added": {timestamp}', index_v1_json)
        # the archive will have the added timestamp for the app and for the apk,
        # both need to be there
        with open("archive/index-v1.json") as f:
            count = sum(1 for line in f if f'"added": {timestamp}' in line)
        self.assertEqual(count, 2)

    def test_whatsnew_from_fastlane_without_cvc_set(self):
        self.fdroid_init_with_prebuilt_keystore()
        Path("metadata/com.politedroid/en-US/changelogs").mkdir(parents=True)
        shutil.copy(FILES / "repo/com.politedroid_6.apk", "repo")
        shutil.copy(FILES / "metadata/com.politedroid.yml", "metadata")
        self.remove_lines("metadata/com.politedroid.yml", ["CurrentVersion:"])
        Path("metadata/com.politedroid/en-US/changelogs/6.txt").write_text(
            "whatsnew test"
        )
        self.assert_run(self.fdroid_cmd + ["update", "--pretty", "--nosign"])
        index_v1_json = Path("repo/index-v1.json").read_text()
        self.assertIn("whatsnew test", index_v1_json)

    def test_metadata_checks(self):
        Path("repo").mkdir()
        shutil.copy(FILES / "urzip.apk", "repo")
        # this should fail because there is no metadata
        self.assert_run_fail(self.fdroid_cmd + ["build"])
        Path("metadata").mkdir()
        shutil.copy(FILES / "metadata/org.smssecure.smssecure.yml", "metadata")
        self.assert_run(self.fdroid_cmd + ["readmeta"])

    def test_ensure_commands_that_dont_need_the_jdk_work_without_a_jdk_configured(self):
        Path("repo").mkdir()
        Path("metadata").mkdir()
        self.update_yaml(
            "metadata/fake.yml",
            {
                "License": "GPL-2.0-only",
                "Summary": "Yup still fake",
                "Categories": ["Internet"],
                "Description": "this is fake",
            },
        )
        # fake that no JDKs are available
        self.update_yaml(
            "config.yml", {"categories": ["Internet"], "java_paths": {}}, replace=True
        )
        local_copy_dir = self.tmp / "fdroid"
        (local_copy_dir / "repo").mkdir(parents=True)
        self.update_yaml(
            "config.yml", {"local_copy_dir": str(local_copy_dir.resolve())}
        )

        subprocess.run(self.fdroid_cmd + ["checkupdates", "--allow-dirty"])
        if shutil.which("gpg"):
            self.assert_run(self.fdroid_cmd + ["gpgsign"])
        self.assert_run(self.fdroid_cmd + ["lint"])
        self.assert_run(self.fdroid_cmd + ["readmeta"])
        self.assert_run(self.fdroid_cmd + ["rewritemeta", "fake"])
        self.assert_run(self.fdroid_cmd + ["deploy"])
        self.assert_run(self.fdroid_cmd + ["scanner"])

        # run these to get their output, but the are not setup, so don't fail
        subprocess.run(self.fdroid_cmd + ["build"])
        subprocess.run(self.fdroid_cmd + ["import"])
        subprocess.run(self.fdroid_cmd + ["install", "-n"])

    def test_config_checks_of_local_copy_dir(self):
        self.assert_run(self.fdroid_cmd + ["init"])
        self.assert_run(self.fdroid_cmd + ["update", "--create-metadata", "--verbose"])
        self.assert_run(self.fdroid_cmd + ["readmeta"])
        local_copy_dir = (self.tmp / "fdroid").resolve()
        local_copy_dir.mkdir()
        self.assert_run(
            self.fdroid_cmd + ["deploy", "--local-copy-dir", local_copy_dir]
        )
        self.assert_run(
            self.fdroid_cmd
            + ["deploy", "--local-copy-dir", local_copy_dir, "--verbose"]
        )

        # this should fail because thisisnotanabsolutepath is not an absolute path
        self.assert_run_fail(
            self.fdroid_cmd + ["deploy", "--local-copy-dir", "thisisnotanabsolutepath"]
        )
        # this should fail because the path doesn't end with "fdroid"
        self.assert_run_fail(
            self.fdroid_cmd
            + [
                "deploy",
                "--local-copy-dir",
                "/tmp/IReallyDoubtThisPathExistsasdfasdf",  # nosec B108
            ]
        )
        # this should fail because the dirname path does not exist
        self.assert_run_fail(
            self.fdroid_cmd
            + [
                "deploy",
                "--local-copy-dir",
                "/tmp/IReallyDoubtThisPathExistsasdfasdf/fdroid",  # nosec B108
            ]
        )

    def test_setup_a_new_repo_from_scratch_using_android_home_and_do_a_local_sync(self):
        self.fdroid_init_with_prebuilt_keystore()
        self.copy_apks_into_repo()
        self.assert_run(self.fdroid_cmd + ["update", "--create-metadata", "--verbose"])
        self.assert_run(self.fdroid_cmd + ["readmeta"])
        self.assertIn("<application id=", Path("repo/index.xml").read_text())

        local_copy_dir = self.tmp / "fdroid"
        self.assert_run(
            self.fdroid_cmd + ["deploy", "--local-copy-dir", local_copy_dir]
        )

        new_tmp_repo = self.tmp / "new_repo"
        new_tmp_repo.mkdir()
        os.chdir(new_tmp_repo)
        self.fdroid_init_with_prebuilt_keystore()
        self.update_yaml("config.yml", {"sync_from_local_copy_dir": True})
        self.assert_run(
            self.fdroid_cmd + ["deploy", "--local-copy-dir", local_copy_dir]
        )

    def test_check_that_android_home_opt_fails_when_dir_does_not_exist_or_is_not_a_dir(
        self,
    ):
        # this should fail because /opt/fakeandroidhome does not exist
        self.assert_run_fail(
            self.fdroid_cmd
            + [
                "init",
                "--keystore",
                "keystore.p12",
                "--android-home",
                "/opt/fakeandroidhome",
            ]
        )
        Path("test_file").touch()
        # this should fail because test_file is not a directory
        self.assert_run_fail(
            self.fdroid_cmd
            + ["init", "--keystore", "keystore.p12", "--android-home", "test_file"]
        )

    def test_check_that_fake_android_home_passes_fdroid_init(self):
        android_home = self.tmp / "android-sdk"
        android_home.mkdir()
        self.create_fake_android_home(android_home)
        self.assert_run(
            self.fdroid_cmd
            + ["init", "--keystore", "keystore.p12", "--android-home", android_home]
        )

    @unittest.skip
    def test_check_that_fdroid_init_fails_when_build_tools_cannot_be_found(self):
        fake_android_home = self.tmp / "android-sdk"
        fake_android_home.mkdir()
        self.create_fake_android_home(fake_android_home)
        (fake_android_home / "build-tools/34.0.0/aapt").unlink()
        self.assert_run_fail(
            self.fdroid_cmd
            + [
                "init",
                "--keystore",
                "keystore.p12",
                "--android-home",
                fake_android_home,
            ]
        )

    def check_that_android_home_opt_overrides_android_home_env_var(self):
        fake_android_home = self.tmp / "android-sdk"
        fake_android_home.mkdir()
        self.create_fake_android_home(fake_android_home)
        self.assert_run(
            self.fdroid_cmd
            + [
                "init",
                "--keystore",
                "keystore.p12",
                "--android-home",
                fake_android_home,
            ]
        )
        # the value set in --android-home should override $ANDROID_HOME
        self.assertIn(str(fake_android_home), Path("config.yml").read_text())

    @unittest.skipUnless(
        "ANDROID_HOME" in os.environ, "runs only with ANDROID_HOME set"
    )
    def setup_a_new_repo_from_scratch_with_keystore_and_android_home_opt_set_on_cmd_line(
        self,
    ):
        """Test with broken setup in ANDROID_HOME.

        In this case, ANDROID_HOME is set to a fake, non-working
        version that will be detected by fdroid as an Android SDK
        install. It should use the path set by --android-home over the
        one in ANDROID_HOME, therefore if it uses the one in
        ANDROID_HOME, it won't work because it is a fake one.  Only
        --android-home provides a working one.

        """
        real_android_home = os.environ["ANDROID_HOME"]
        fake_android_home = self.tmp / "android-sdk"
        fake_android_home.mkdir()
        env = os.environ.copy()
        env["ANDROID_HOME"] = str(fake_android_home)
        self.assert_run(
            self.fdroid_cmd
            + [
                "init",
                "--keystore",
                "keystore.p12",
                "--android-home",
                real_android_home,
                "--no-prompt",
            ],
            env=env,
        )
        self.assertTrue(Path("keystore.p12").is_file())
        self.copy_apks_into_repo()
        self.assert_run(
            self.fdroid_cmd + ["update", "--create-metadata", "--verbose"], env=env
        )
        self.assert_run(self.fdroid_cmd + ["readmeta"], env=env)
        self.assertIn("<application id=", Path("repo/index.xml").read_text())
        self.assertTrue(Path("repo/index.jar").is_file())
        self.assertTrue(Path("repo/index-v1.jar").is_file())
        apkcache = Path("tmp/apkcache.json")
        self.assertTrue(apkcache.is_file())
        self.assertTrue(apkcache.stat().st_size > 0)

    def test_check_duplicate_files_are_properly_handled_by_fdroid_update(self):
        self.fdroid_init_with_prebuilt_keystore()
        Path("metadata").mkdir()
        shutil.copy(FILES / "metadata/obb.mainpatch.current.yml", "metadata")
        shutil.copy(FILES / "repo/obb.mainpatch.current_1619.apk", "repo")
        shutil.copy(
            FILES / "repo/obb.mainpatch.current_1619_another-release-key.apk", "repo"
        )
        self.assert_run(self.fdroid_cmd + ["update", "--pretty"])
        index_xml = Path("repo/index.xml").read_text()
        index_v1_json = Path("repo/index-v1.json").read_text()
        self.assertNotIn(
            "obb.mainpatch.current_1619_another-release-key.apk", index_xml
        )
        self.assertIn("obb.mainpatch.current_1619.apk", index_xml)
        self.assertIn("obb.mainpatch.current_1619.apk", index_v1_json)
        self.assertIn(
            "obb.mainpatch.current_1619_another-release-key.apk", index_v1_json
        )
        # die if there are exact duplicates
        shutil.copy(FILES / "repo/obb.mainpatch.current_1619.apk", "repo/duplicate.apk")
        self.assert_run_fail(self.fdroid_cmd + ["update"])

    def test_setup_new_repo_from_scratch_using_android_home_env_var_putting_apks_in_repo_first(
        self,
    ):
        Path("repo").mkdir()
        self.copy_apks_into_repo()
        self.fdroid_init_with_prebuilt_keystore()
        self.assert_run(self.fdroid_cmd + ["update", "--create-metadata", "--verbose"])
        self.assert_run(self.fdroid_cmd + ["readmeta"])
        self.assertIn("<application id=", Path("repo/index.xml").read_text())

    def test_setup_a_new_repo_from_scratch_and_generate_a_keystore(self):
        self.assert_run(self.fdroid_cmd + ["init", "--keystore", "keystore.p12"])
        self.assertTrue(Path("keystore.p12").is_file())
        self.copy_apks_into_repo()
        self.assert_run(self.fdroid_cmd + ["update", "--create-metadata", "--verbose"])
        self.assert_run(self.fdroid_cmd + ["readmeta"])
        self.assertIn("<application id=", Path("repo/index.xml").read_text())
        self.assertTrue(Path("repo/index.jar").is_file())
        self.assertTrue(Path("repo/index-v1.jar").is_file())
        apkcache = Path("tmp/apkcache.json")
        self.assertTrue(apkcache.is_file())
        self.assertTrue(apkcache.stat().st_size > 0)

    def test_setup_a_new_repo_manually_and_generate_a_keystore(self):
        self.assertFalse(Path("keystore.p12").exists())
        # this should fail because this repo has no keystore
        self.assert_run_fail(self.fdroid_cmd + ["update"])
        self.assert_run(self.fdroid_cmd + ["update", "--create-key"])
        self.assertTrue(Path("keystore.p12").is_file())
        self.copy_apks_into_repo()
        self.assert_run(self.fdroid_cmd + ["update", "--create-metadata", "--verbose"])
        self.assert_run(self.fdroid_cmd + ["readmeta"])
        self.assertIn("<application id=", Path("repo/index.xml").read_text())
        self.assertTrue(Path("repo/index.jar").is_file())
        self.assertTrue(Path("repo/index-v1.jar").is_file())
        apkcache = Path("tmp/apkcache.json")
        self.assertTrue(apkcache.is_file())
        self.assertTrue(apkcache.stat().st_size > 0)

    def test_setup_a_new_repo_from_scratch_generate_a_keystore_then_add_apk_and_update(
        self,
    ):
        self.assert_run(self.fdroid_cmd + ["init", "--keystore", "keystore.p12"])
        self.assertTrue(Path("keystore.p12").is_file())
        self.copy_apks_into_repo()
        self.assert_run(self.fdroid_cmd + ["update", "--create-metadata", "--verbose"])
        self.assert_run(self.fdroid_cmd + ["readmeta"])
        self.assertIn("<application id=", Path("repo/index.xml").read_text())
        self.assertTrue(Path("repo/index.jar").is_file())
        self.assertTrue(Path("repo/index-v1.jar").is_file())

        if not Path("repo/info.guardianproject.urzip_100.apk").exists():
            shutil.copy(FILES / "urzip.apk", "repo")
        self.assert_run(self.fdroid_cmd + ["update", "--create-metadata", "--verbose"])
        self.assert_run(self.fdroid_cmd + ["readmeta"])
        self.assertIn("<application id=", Path("repo/index.xml").read_text())
        self.assertTrue(Path("repo/index.jar").is_file())
        self.assertTrue(Path("repo/index-v1.jar").is_file())
        apkcache = Path("tmp/apkcache.json")
        self.assertTrue(apkcache.is_file())
        self.assertTrue(apkcache.stat().st_size > 0)
        self.assertIn("<application id=", Path("repo/index.xml").read_text())

    def test_setup_a_new_repo_from_scratch_with_a_hsm_or_smartcard(self):
        self.assert_run(self.fdroid_cmd + ["init", "--keystore", "NONE"])
        self.assertTrue(Path("opensc-fdroid.cfg").is_file())
        self.assertFalse(Path("NONE").exists())

    def test_setup_a_new_repo_with_no_keystore_add_apk_and_update(self):
        Path("fdroid-icon.png").touch()
        Path("repo").mkdir()
        shutil.copy(FILES / "urzip.apk", "repo")
        # this should fail because this repo has no keystore
        self.assert_run_fail(
            self.fdroid_cmd + ["update", "--create-metadata", "--verbose"]
        )

        # now set up fake, non-working keystore setup
        Path("keystore.p12").touch()
        self.update_yaml(
            "config.yml",
            {
                "keystore": "keystore.p12",
                "repo_keyalias": "foo",
                "keystorepass": "foo",
                "keypass": "foo",
            },
        )
        # this should fail because this repo has a bad/fake keystore
        self.assert_run_fail(
            self.fdroid_cmd + ["update", "--create-metadata", "--verbose"]
        )

    def test_copy_tests_repo_update_with_binary_transparency_log(self):
        self.fdroid_init_with_prebuilt_keystore()
        shutil.copytree(FILES / "repo", "repo", dirs_exist_ok=True)
        shutil.copytree(FILES / "metadata", "metadata")
        git_remote = self.tmp / "git_remote"
        self.update_yaml("config.yml", {"binary_transparency_remote": str(git_remote)})
        self.assert_run(self.fdroid_cmd + ["update", "--verbose"])
        self.assert_run(self.fdroid_cmd + ["deploy", "--verbose"])
        self.assertIn("<application id=", Path("repo/index.xml").read_text())
        self.assertTrue(Path("repo/index.jar").is_file())
        self.assertTrue(Path("repo/index-v1.jar").is_file())
        os.chdir("binary_transparency")
        proc = self.assert_run(
            ["git", "rev-list", "--count", "HEAD"], capture_output=True
        )
        self.assertEqual(int(proc.stdout), 2)
        os.chdir(git_remote)
        proc = self.assert_run(
            ["git", "rev-list", "--count", "HEAD"], capture_output=True
        )
        self.assertEqual(int(proc.stdout), 2)

    def test_setup_a_new_repo_with_keystore_with_apk_update_then_without_key(self):
        shutil.copy(FILES / "keystore.jks", "keystore.jks")
        self.fdroid_init_with_prebuilt_keystore("keystore.jks")
        shutil.copy(FILES / "urzip.apk", "repo")
        self.assert_run(self.fdroid_cmd + ["update", "--create-metadata", "--verbose"])
        self.assert_run(self.fdroid_cmd + ["readmeta"])
        self.assertIn("<application id=", Path("repo/index.xml").read_text())
        self.assertTrue(Path("repo/index.jar").is_file())
        self.assertTrue(Path("repo/index-v1.jar").is_file())
        apkcache = Path("tmp/apkcache.json")
        self.assertTrue(apkcache.is_file())
        self.assertTrue(apkcache.stat().st_size > 0)

        # now set fake repo_keyalias
        self.update_yaml("config.yml", {"repo_keyalias": "fake"})
        # this should fail because this repo has a bad repo_keyalias
        self.assert_run_fail(self.fdroid_cmd + ["update"])

        # this should fail because a keystore is already there
        self.assert_run_fail(self.fdroid_cmd + ["update", "--create-key"])

        # now actually create the key with the existing settings
        Path("keystore.jks").unlink()
        self.assert_run(self.fdroid_cmd + ["update", "--create-key"])
        self.assertTrue(Path("keystore.jks").is_file())

    def test_setup_a_new_repo_from_scratch_using_android_home_env_var_with_git_mirror(
        self,
    ):
        server_git_mirror = self.tmp / "server_git_mirror"
        server_git_mirror.mkdir()
        self.assert_run(
            ["git", "-C", server_git_mirror, "init", "--initial-branch", "master"]
        )
        self.assert_run(
            [
                "git",
                "-C",
                server_git_mirror,
                "config",
                "receive.denyCurrentBranch",
                "updateInstead",
            ]
        )

        self.fdroid_init_with_prebuilt_keystore()
        self.update_yaml(
            "config.yml",
            {"archive_older": 3, "servergitmirrors": str(server_git_mirror)},
        )
        for f in FILES.glob("repo/com.politedroid_[345].apk"):
            shutil.copy(f, "repo")
        self.assert_run(self.fdroid_cmd + ["update", "--create-metadata"])
        self.assert_run(self.fdroid_cmd + ["deploy"])
        git_mirror = Path("git-mirror")
        self.assertTrue((git_mirror / "fdroid/repo/com.politedroid_3.apk").is_file())
        self.assertTrue((git_mirror / "fdroid/repo/com.politedroid_4.apk").is_file())
        self.assertTrue((git_mirror / "fdroid/repo/com.politedroid_5.apk").is_file())
        self.assertTrue(
            (server_git_mirror / "fdroid/repo/com.politedroid_3.apk").is_file()
        )
        self.assertTrue(
            (server_git_mirror / "fdroid/repo/com.politedroid_4.apk").is_file()
        )
        self.assertTrue(
            (server_git_mirror / "fdroid/repo/com.politedroid_5.apk").is_file()
        )
        (git_mirror / ".git/test-stamp").write_text(str(datetime.now()))

        # add one more APK to trigger archiving
        shutil.copy(FILES / "repo/com.politedroid_6.apk", "repo")
        self.assert_run(self.fdroid_cmd + ["update"])
        self.assert_run(self.fdroid_cmd + ["deploy"])
        self.assertTrue(Path("archive/com.politedroid_3.apk").is_file())
        self.assertFalse((git_mirror / "fdroid/archive/com.politedroid_3.apk").exists())
        self.assertFalse(
            (server_git_mirror / "fdroid/archive/com.politedroid_3.apk").exists()
        )
        self.assertTrue((git_mirror / "fdroid/repo/com.politedroid_4.apk").is_file())
        self.assertTrue((git_mirror / "fdroid/repo/com.politedroid_5.apk").is_file())
        self.assertTrue((git_mirror / "fdroid/repo/com.politedroid_6.apk").is_file())
        self.assertTrue(
            (server_git_mirror / "fdroid/repo/com.politedroid_4.apk").is_file()
        )
        self.assertTrue(
            (server_git_mirror / "fdroid/repo/com.politedroid_5.apk").is_file()
        )
        self.assertTrue(
            (server_git_mirror / "fdroid/repo/com.politedroid_6.apk").is_file()
        )
        before = sum(
            f.stat().st_size for f in (git_mirror / ".git").glob("**/*") if f.is_file()
        )

        self.update_yaml("config.yml", {"git_mirror_size_limit": "60kb"})
        self.assert_run(self.fdroid_cmd + ["update"])
        self.assert_run(self.fdroid_cmd + ["deploy"])
        self.assertTrue(Path("archive/com.politedroid_3.apk").is_file())
        self.assertFalse(
            (server_git_mirror / "fdroid/archive/com.politedroid_3.apk").exists()
        )
        after = sum(
            f.stat().st_size for f in (git_mirror / ".git").glob("**/*") if f.is_file()
        )
        self.assertFalse((git_mirror / ".git/test-stamp").exists())
        self.assert_run(["git", "-C", git_mirror, "gc"])
        self.assert_run(["git", "-C", server_git_mirror, "gc"])
        self.assertGreater(before, after)

    def test_sign_binary_repo_in_offline_box_then_publishing_from_online_box(self):
        offline_root = self.tmp / "offline_root"
        offline_root.mkdir()
        local_copy_dir = self.tmp / "local_copy_dir/fdroid"
        local_copy_dir.mkdir(parents=True)
        online_root = self.tmp / "online_root"
        online_root.mkdir()
        server_web_root = self.tmp / "server_web_root/fdroid"
        server_web_root.mkdir(parents=True)

        # create offline binary transparency log
        (offline_root / "binary_transparency").mkdir()
        os.chdir(offline_root / "binary_transparency")
        self.assert_run(["git", "init", "--initial-branch", "master"])

        # fake git remote server for binary transparency log
        binary_transparency_remote = self.tmp / "binary_transparency_remote"
        binary_transparency_remote.mkdir()

        # fake git remote server for repo mirror
        server_git_mirror = self.tmp / "server_git_mirror"
        server_git_mirror.mkdir()
        os.chdir(server_git_mirror)
        self.assert_run(["git", "init", "--initial-branch", "master"])
        self.assert_run(["git", "config", "receive.denyCurrentBranch", "updateInstead"])

        os.chdir(offline_root)
        self.fdroid_init_with_prebuilt_keystore()
        shutil.copytree(FILES / "repo", "repo", dirs_exist_ok=True)
        shutil.copytree(FILES / "metadata", "metadata")
        Path("unsigned").mkdir()
        shutil.copy(FILES / "urzip-release-unsigned.apk", "unsigned")
        self.update_yaml(
            "config.yml",
            {
                "archive_older": 3,
                "mirrors": [
                    "http://foo.bar/fdroid",
                    "http://asdflkdsfjafdsdfhkjh.onion/fdroid",
                ],
                "servergitmirrors": str(server_git_mirror),
                "local_copy_dir": str(local_copy_dir),
            },
        )
        self.assert_run(self.fdroid_cmd + ["update", "--pretty"])
        index_xml = Path("repo/index.xml").read_text()
        self.assertIn("<application id=", index_xml)
        self.assertIn("/fdroid/repo</mirror>", index_xml)
        mirror_cnt = sum(1 for line in index_xml.splitlines() if "<mirror>" in line)
        self.assertEqual(mirror_cnt, 2)

        archive_xml = Path("archive/index.xml").read_text()
        self.assertIn("/fdroid/archive</mirror>", archive_xml)
        mirror_cnt = sum(1 for line in archive_xml.splitlines() if "<mirror>" in line)
        self.assertEqual(mirror_cnt, 2)

        os.chdir("binary_transparency")
        proc = self.assert_run(
            ["git", "rev-list", "--count", "HEAD"], capture_output=True
        )
        self.assertEqual(int(proc.stdout), 1)
        os.chdir(offline_root)
        self.assert_run(self.fdroid_cmd + ["deploy", "--verbose"])
        self.assertTrue(
            Path(local_copy_dir / "unsigned/urzip-release-unsigned.apk").is_file()
        )
        self.assertIn(
            "<application id=", (local_copy_dir / "repo/index.xml").read_text()
        )
        os.chdir(online_root)
        self.update_yaml(
            "config.yml",
            {
                "local_copy_dir": str(local_copy_dir),
                "sync_from_local_copy_dir": True,
                "serverwebroot": str(server_web_root),
                "servergitmirrors": str(server_git_mirror),
                "binary_transparency_remote": str(binary_transparency_remote),
            },
        )
        self.assert_run(self.fdroid_cmd + ["deploy", "--verbose"])
        self.assertTrue((online_root / "unsigned/urzip-release-unsigned.apk").is_file())
        self.assertTrue(
            (server_web_root / "unsigned/urzip-release-unsigned.apk").is_file()
        )
        os.chdir(binary_transparency_remote)
        proc = self.assert_run(
            ["git", "rev-list", "--count", "HEAD"], capture_output=True
        )
        self.assertEqual(int(proc.stdout), 1)
        os.chdir(server_git_mirror)
        proc = self.assert_run(
            ["git", "rev-list", "--count", "HEAD"], capture_output=True
        )
        self.assertEqual(int(proc.stdout), 1)

    @unittest.skipUnless(USE_APKSIGNER, "requires apksigner")
    def test_extracting_and_publishing_with_developer_signature(self):
        self.fdroid_init_with_prebuilt_keystore()
        self.update_yaml(
            "config.yml",
            {
                "keydname": "CN=Birdman, OU=Cell, O=Alcatraz, L=Alcatraz, S=California, C=US"
            },
        )
        Path("metadata").mkdir()
        shutil.copy(FILES / "metadata/com.politedroid.yml", "metadata")
        Path("unsigned").mkdir()
        shutil.copy(FILES / "repo/com.politedroid_6.apk", "unsigned")
        self.assert_run(
            self.fdroid_cmd + ["signatures", "unsigned/com.politedroid_6.apk"]
        )
        self.assertTrue(
            Path("metadata/com.politedroid/signatures/6/MANIFEST.MF").is_file()
        )
        self.assertTrue(
            Path("metadata/com.politedroid/signatures/6/RELEASE.RSA").is_file()
        )
        self.assertTrue(
            Path("metadata/com.politedroid/signatures/6/RELEASE.SF").is_file()
        )
        self.assertFalse(Path("repo/com.politedroid_6.apk").exists())
        self.assert_run(self.fdroid_cmd + ["publish"])
        self.assertTrue(Path("repo/com.politedroid_6.apk").is_file())
        if shutil.which("apksigner"):
            self.assert_run(["apksigner", "verify", "repo/com.politedroid_6.apk"])
        if shutil.which("jarsigner"):
            self.assert_run(["jarsigner", "-verify", "repo/com.politedroid_6.apk"])

    @unittest.skipUnless(shutil.which("wget"), "requires wget")
    def test_mirroring_a_repo(self):
        """Start a local webserver to mirror a fake repo from.

        Proxy settings via environment variables can interfere with
        this test. The requests library will automatically pick up
        proxy settings from environment variables. Proxy settings can
        force the local connection over the proxy, which might not
        support that, then this fails with an error like 405 or
        others.

        """
        tmp_test = self.tmp / "test"
        tmp_test.mkdir()
        shutil.copytree(FILES, tmp_test, dirs_exist_ok=True)
        os.chdir(tmp_test)
        Path("archive").mkdir()
        shutil.copy("repo/index-v1.json", self.tmp_repo)
        self.assert_run(self.fdroid_cmd + ["update"])
        self.assert_run(self.fdroid_cmd + ["signindex"])
        shutil.move(self.tmp_repo / "index-v1.json", "repo/index-v1.json")

        class RequestHandler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=tmp_test, **kwargs)

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), RequestHandler)
        threading.Thread(target=httpd.serve_forever).start()

        os.chdir(self.tmp_repo)
        host, port = httpd.socket.getsockname()
        url, output_dir = f"http://{host}:{port}/", Path(f"{host}:{port}")
        env = os.environ.copy()
        env.pop("http_proxy", None)
        self.assert_run(self.fdroid_cmd + ["mirror", url], env=env)
        self.assertTrue((output_dir / "repo/souch.smsbypass_9.apk").is_file())
        self.assertTrue((output_dir / "repo/icons-640/souch.smsbypass.9.png").is_file())
        # the index shouldn't be saved unless it was verified
        self.assertFalse((output_dir / "repo/index-v1.jar").exists())
        self.assert_run_fail(
            self.fdroid_cmd + ["mirror", f"{url}?fingerprint=asdfasdf"], env=env
        )
        self.assertFalse((output_dir / "repo/index-v1.jar").exists())
        self.assert_run(
            self.fdroid_cmd
            + [
                "mirror",
                f"{url}?fingerprint=F49AF3F11EFDDF20DFFD70F5E3117B9976674167ADCA280E6B1932A0601B26F6",
            ],
            env=env,
        )
        self.assertTrue((output_dir / "repo/index-v1.jar").is_file())

        httpd.shutdown()

    def test_recovering_from_broken_git_submodules(self):
        Path("foo").mkdir()
        Path("bar").mkdir()
        os.chdir("foo")
        self.assert_run(["git", "init"])
        Path("a").write_text("a")
        self.assert_run(["git", "add", "a"])
        self.assert_run(["git", "commit", "-m", "a"])

        os.chdir("../bar")
        self.assert_run(["git", "init"])
        self.assert_run(
            ["git", "submodule", "add", f"file://{Path().resolve()}/../foo", "baz"]
        )
        Path(".gitmodules").unlink()
        self.assert_run(["git", "commit", "-am", "a"])
        shutil.rmtree("baz")
        self.assert_run(["git", "checkout", "baz"])
        self.assert_run(["git", "tag", "2"])

        os.chdir("..")
        Path("repo").mkdir()
        Path("metadata").mkdir()
        self.update_yaml(
            "metadata/fake.yml",
            {
                "RepoType": "git",
                "Repo": f"file://{Path().resolve()}/bar",
                "AutoUpdateMode": "Version",
                "UpdateCheckMode": "Tags",
                "UpdateCheckData": "|||",
                "CurrentVersion": 1,
                "CurrentVersionCode": 1,
            },
        )
        self.assert_run(self.fdroid_cmd + ["checkupdates", "--allow-dirty"])
        self.assertIn("CurrentVersionCode: 2", Path("metadata/fake.yml").read_text())

    def test_checkupdates_ignore_broken_submodule(self):
        Path("foo").mkdir()
        Path("bar").mkdir()
        os.chdir("foo")
        self.assert_run(["git", "init"])
        Path("a").write_text("a")
        self.assert_run(["git", "add", "a"])
        self.assert_run(["git", "commit", "-m", "a"])

        os.chdir("../bar")
        self.assert_run(["git", "init"])
        self.assert_run(
            ["git", "submodule", "add", f"file://{Path().resolve()}/../foo", "baz"]
        )
        self.assert_run(["git", "commit", "-am", "a"])
        self.assert_run(["git", "tag", "2"])

        os.chdir("../foo")
        # delete the commit referenced in bar
        self.assert_run(["git", "commit", "--amend", "-m", "aa"])
        self.assert_run(["git", "reflog", "expire", "--expire", "now", "--all"])
        self.assert_run(["git", "gc", "--aggressive", "--prune=now"])

        os.chdir("..")

        Path("repo").mkdir()
        Path("metadata").mkdir()
        self.update_yaml(
            "metadata/fake.yml",
            {
                "RepoType": "git",
                "Repo": f"file://{Path().resolve()}/bar",
                "Builds": [{"versionName": 1, "versionCode": 1, "submodules": True}],
                "AutoUpdateMode": "Version",
                "UpdateCheckMode": "Tags",
                "UpdateCheckData": "|||",
                "CurrentVersion": 1,
                "CurrentVersionCode": 1,
            },
        )
        self.assert_run(self.fdroid_cmd + ["checkupdates", "--allow-dirty"])
        self.assertIn("CurrentVersionCode: 2", Path("metadata/fake.yml").read_text())

    def test_checkupdates_check_version_in_submodule(self):
        Path("app").mkdir()
        Path("sub").mkdir()
        os.chdir("sub")
        self.assert_run(["git", "init"])
        Path("ver").write_text("1")
        self.assert_run(["git", "add", "ver"])
        self.assert_run(["git", "commit", "-m", "1"])

        os.chdir("../app")
        self.assert_run(["git", "init"])
        self.assert_run(
            ["git", "submodule", "add", f"file://{Path().resolve()}/../sub"]
        )
        self.assert_run(["git", "commit", "-am", "1"])
        self.assert_run(["git", "tag", "1"])

        os.chdir("../sub")
        Path("ver").write_text("2")
        self.assert_run(["git", "commit", "-am", "2"])

        os.chdir("../app")
        self.assert_run(["git", "init"])
        self.assert_run(["git", "submodule", "update", "--remote"])
        self.assert_run(["git", "commit", "-am", "2"])

        os.chdir("..")
        Path("repo").mkdir()
        Path("metadata").mkdir()
        self.update_yaml(
            "metadata/fake.yml",
            {
                "RepoType": "git",
                "Repo": f"file://{Path().resolve()}/app",
                "Builds": [{"versionName": 0, "versionCode": 0, "submodules": True}],
                "AutoUpdateMode": "Version",
                "UpdateCheckMode": "Tags",
                "UpdateCheckData": r"sub/ver|(\d)||",
                "CurrentVersion": 0,
                "CurrentVersionCode": 0,
            },
        )
        self.assert_run(
            self.fdroid_cmd + ["checkupdates", "--allow-dirty", "--auto", "-v"]
        )
        self.assertIn("CurrentVersionCode: 1", Path("metadata/fake.yml").read_text())

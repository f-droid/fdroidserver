#!/usr/bin/env python3
#
# dscanner.py - part of the FDroid server tools
# Copyright (C) 2016-2017 Shawn Gustaw <self@shawngustaw.com>
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

import logging
import os
import json
import sys
from time import sleep
from argparse import ArgumentParser
from subprocess import CalledProcessError, check_output

from . import _
from . import common
from . import metadata

try:
    from docker import Client
except ImportError:
    logging.error(("Docker client not installed."
                   "Install it using pip install docker-py"))

config = None
options = None


class DockerConfig:
    ALIAS = "dscanner"
    CONTAINER = "dscanner/fdroidserver"
    EMULATOR = "android-19"
    ARCH = "armeabi-v7a"


class DockerDriver(object):
    """
    Handles all the interactions with the docker container the
    Android emulator runs in.
    """
    class Commands:
        build = ['docker', 'build', '--no-cache=false', '--pull=true',
                 '--quiet=false', '--rm=true', '-t',
                 '{0}:latest'.format(DockerConfig.CONTAINER), '.']
        run = [
            'docker', 'run',
            '-e', '"EMULATOR={0}"'.format(DockerConfig.EMULATOR),
            '-e', '"ARCH={0}"'.format(DockerConfig.ARCH),
            '-d', '-P', '--name',
            '{0}'.format(DockerConfig.ALIAS), '--log-driver=json-file',
            DockerConfig.CONTAINER]
        start = ['docker', 'start', '{0}'.format(DockerConfig.ALIAS)]
        inspect = ['docker', 'inspect', '{0}'.format(DockerConfig.ALIAS)]
        pm_list = 'adb shell "pm list packages"'
        install_drozer = "docker exec {0} python /home/drozer/install_agent.py"
        run_drozer = 'python /home/drozer/drozer.py {0}'
        copy_to_container = 'docker cp "{0}" {1}:{2}'
        copy_from_container = 'docker cp {0}:{1} "{2}"'

    def __init__(self, init_only=False, fresh_start=False, clean_only=False):
        self.container_id = None
        self.ip_address = None

        self.cli = Client(base_url='unix://var/run/docker.sock')

        if fresh_start or clean_only:
            self.clean()

        if clean_only:
            logging.info("Cleaned containers and quitting.")
            exit(0)

        self.init_docker()

        if init_only:
            logging.info("Initialized and quitting.")
            exit(0)

    def _copy_to_container(self, src_path, dest_path):
        """
        Copies a file (presumed to be an apk) from src_path
        to home directory on container.
        """
        path = '/home/drozer/{path}.apk'.format(path=dest_path)
        command = self.Commands.copy_to_container.format(src_path,
                                                         self.container_id,
                                                         path)

        try:
            check_output(command, shell=True)
        except CalledProcessError as e:
            logging.error(('Command "{command}" failed with '
                           'error code {code}'.format(command=command,
                                                      code=e.returncode)))
            raise

    def _copy_from_container(self, src_path, dest_path):
        """
        Copies a file from src_path on the container to
        dest_path on the host machine.
        """
        command = self.Commands.copy_from_container.format(self.container_id,
                                                           src_path,
                                                           dest_path)
        try:
            check_output(command, shell=True)
        except CalledProcessError as e:
            logging.error(('Command "{command}" failed with '
                           'error code {code}'.format(command=command,
                                                      code=e.returncode)))
            raise

        logging.info("Log stored at {path}".format(path=dest_path))

    def _adb_install_apk(self, apk_path):
        """
        Installs an apk on the device running in the container
        using adb.
        """
        logging.info("Attempting to install an apk.")
        exec_id = self.cli.exec_create(
            self.container_id, 'adb install {0}'
            .format(apk_path)
            )['Id']
        output = self.cli.exec_start(exec_id).decode('utf-8')

        if "INSTALL_PARSE_FAILED_NO_CERTIFICATES" in output:
            raise Exception('Install parse failed, no certificates')
        elif "INSTALL_FAILED_ALREADY_EXISTS" in output:
            logging.info("APK already installed. Skipping.")
        elif "Success" not in output:
            logging.error("APK didn't install properly")
            return False
        return True

    def _adb_uninstall_apk(self, app_id):
        """
        Uninstalls an application from the device running in the container
        via its app_id.
        """
        logging.info(
            "Uninstalling {app_id} from the emulator."
            .format(app_id=app_id)
            )
        exec_id = self.cli.exec_create(
            self.container_id,
            'adb uninstall {0}'.format(app_id)
            )['Id']
        output = self.cli.exec_start(exec_id).decode('utf-8')

        if 'Success' in output:
            logging.info("Successfully uninstalled.")

        return True

    def _verify_apk_install(self, app_id):
        """
        Checks that the app_id is installed on the device running in the
        container.
        """
        logging.info(
            "Verifying {app} is installed on the device."
            .format(app=app_id)
            )
        exec_id = self.cli.exec_create(
            self.container_id, self.Commands.pm_list
            )['Id']
        output = self.cli.exec_start(exec_id).decode('utf-8')

        if ("Could not access the Package Manager" in output or
                "device offline" in output):
            logging.info("Device or package manager isn't up")

        if app_id.split('_')[0] in output:   # TODO: this is a temporary fix
            logging.info("{app} is installed.".format(app=app_id))
            return True

        logging.error("APK not found in packages list on emulator.")

    def _delete_file(self, path):
        """
        Deletes file off the container to preserve space if scanning many apps
        """
        command = "rm {path}".format(path=path)
        exec_id = self.cli.exec_create(self.container_id, command)['Id']
        logging.info("Deleting {path} on the container.".format(path=path))
        self.cli.exec_start(exec_id)

    def _install_apk(self, apk_path, app_id):
        """
        Installs apk found at apk_path on the emulator. Will then
        verify it installed properly by looking up its app_id in
        the package manager.
        """
        if not all([self.container_id, self.ip_address]):
            # TODO: maybe have this fail nicely
            raise Exception("Went to install apk and couldn't find container")

        path = "/home/drozer/{app_id}.apk".format(app_id=app_id)
        self._copy_to_container(apk_path, app_id)
        self._adb_install_apk(path)
        self._verify_apk_install(app_id)
        self._delete_file(path)

    def _install_drozer(self):
        """
        Performs all the initialization of drozer within the emulator.
        """
        logging.info("Attempting to install com.mwr.dz on the emulator")
        logging.info("This could take a while so be patient...")
        logging.info(("We need to wait for the device to boot AND"
                      " the package manager to come online."))
        command = self.Commands.install_drozer.format(self.container_id)
        try:
            output = check_output(command,
                                  shell=True).decode('utf-8')
        except CalledProcessError as e:
            logging.error(('Command "{command}" failed with '
                           'error code {code}'.format(command=command,
                                                      code=e.returncode)))
            raise

        if 'Installed ok' in output:
            return True

    def _run_drozer_scan(self, app):
        """
        Runs the drozer agent which connects to the app running
        on the emulator.
        """
        logging.info("Running the drozer agent")
        exec_id = self.cli.exec_create(
            self.container_id,
            self.Commands.run_drozer.format(app)
            )['Id']
        self.cli.exec_start(exec_id)

    def _container_is_running(self):
        """
        Checks whether the emulator container is running.
        """
        for container in self.cli.containers():
            if DockerConfig.ALIAS in container['Image']:
                return True

    def _docker_image_exists(self):
        """
        Check whether the docker image exists already.
        If this returns false we'll need to build the image
        from the DockerFile.
        """
        for image in self.cli.images():
            for tag in image['RepoTags']:
                if DockerConfig.ALIAS in tag:
                    return True

    _image_queue = {}

    def _build_docker_image(self):
        """
        Builds the docker container so we can run the android emulator
        inside it.
        """
        logging.info("Pulling the container from docker hub")
        logging.info("Image is roughly 5 GB so be patient")

        logging.info("(Progress output is slow and requires a tty.)")
        # we pause briefly to narrow race condition windows of opportunity
        sleep(1)

        is_a_tty = os.isatty(sys.stdout.fileno())

        for output in self.cli.pull(
                DockerConfig.CONTAINER,
                stream=True,
                tag="latest"):
            if not is_a_tty:
                # run silent, run quick
                continue
            try:
                p = json.loads(output.decode('utf-8'))
                p_id = p['id']
                self._image_queue[p_id] = p
                t, c, j = 1, 1, 0
                for k in sorted(self._image_queue):
                    j += 1
                    v = self._image_queue[k]
                    vd = v['progressDetail']
                    t += vd['total']
                    c += vd['current']
                msg = "\rDownloading: {0}/{1} {2}% [{3} jobs]"
                msg = msg.format(c, t, int(c / t * 100), j)
                sys.stdout.write(msg)
                sys.stdout.flush()
            except Exception:
                pass
        print("\nDONE!\n")

    def _verify_apk_exists(self, full_apk_path):
        """
        Verifies that the apk path we have is actually a file.
        """
        return os.path.isfile(full_apk_path)

    def init_docker(self):
        """
        Perform all the initialization required before a drozer scan.
        1. build the image
        2. run the container
        3. install drozer and enable the service within the app
        """
        built = self._docker_image_exists()

        if not built:
            self._build_docker_image()

        running = self._container_is_running()

        if not running:
            logging.info('Trying to run container...')
            try:
                check_output(self.Commands.run)
            except CalledProcessError as e:
                logging.error((
                    'Command "{command}" failed with error code {code}'
                    .format(command=self.Commands.run, code=e.returncode)
                    ))
            running = self._container_is_running()

        if not running:
            logging.info('Trying to start container...')
            try:
                check_output(self.Commands.start)
            except CalledProcessError as e:
                logging.error((
                    'Command "{command}" failed with error code {code}'
                    .format(command=self.Commands.run, code=e.returncode)
                    ))
            running = self._container_is_running()

        if not running:
            raise Exception("Running container not found, critical error.")

        containers = self.cli.containers()

        for container in containers:
            if DockerConfig.ALIAS in container['Image']:
                self.container_id = container['Id']
                n = container['NetworkSettings']['Networks']
                self.ip_address = n['bridge']['IPAddress']
                break

        if not self.container_id or not self.ip_address:
            logging.error("No ip address or container id found.")
            exit(1)

        if self._verify_apk_install('com.mwr.dz'):
            return

        self._install_drozer()

    def clean(self):
        """
        Clean up all the containers made by this script.
        Should be run after the drozer scan completes.
        """
        for container in self.cli.containers():
            if DockerConfig.ALIAS in container['Image']:
                logging.info("Removing container {0}".format(container['Id']))
                self.cli.remove_container(container['Id'], force=True)

    def perform_drozer_scan(self, apk_path, app_id):
        """
        Entrypoint for scanning an android app. Performs the following steps:
        1. installs an apk on the device
        2. runs a drozer scan
        3. copies the report off the container
        4. uninstalls the apk to save space on the device
        """
        self._install_apk(apk_path, app_id)
        logging.info("Running the drozer scan.")
        self._run_drozer_scan(app_id)
        logging.info("Scan finished. Moving the report off the container")
        dest = apk_path + '.drozer'
        self._copy_from_container('/tmp/drozer_report.log', dest)
        self._adb_uninstall_apk(app_id)


def main():
    global config, options

    # Parse command line...
    parser = ArgumentParser(
        usage="%(prog)s [options] [APPID[:VERCODE] [APPID[:VERCODE] ...]]"
        )
    common.setup_global_opts(parser)

    parser.add_argument(
        "app_id", nargs='*',
        help=_("applicationId with optional versionCode in the form APPID[:VERCODE]"))
    parser.add_argument(
        "-l", "--latest", action="store_true", default=False,
        help=_("Scan only the latest version of each package"))
    parser.add_argument(
        "--clean-after", default=False, action='store_true',
        help=_("Clean after all scans have finished"))
    parser.add_argument(
        "--clean-before", default=False, action='store_true',
        help=_("Clean before the scans start and rebuild the container"))
    parser.add_argument(
        "--clean-only", default=False, action='store_true',
        help=_("Clean up all containers and then exit"))
    parser.add_argument(
        "--init-only", default=False, action='store_true',
        help=_("Prepare Drozer to run a scan"))
    parser.add_argument(
        "--repo-path", default="repo", action="store",
        help=_("Override path for repo APKs (default: ./repo)"))

    options = parser.parse_args()
    config = common.read_config(options)

    if not os.path.isdir(options.repo_path):
        sys.stderr.write("repo-path not found: \"" + options.repo_path + "\"")
        exit(1)

    # Read all app and srclib metadata
    allapps = metadata.read_metadata()
    apps = common.read_app_args(options.app_id, allapps, True)

    docker = DockerDriver(
        init_only=options.init_only,
        fresh_start=options.clean_before,
        clean_only=options.clean_only
    )

    if options.clean_before:
        docker.clean()

    if options.clean_only:
        exit(0)

    for app_id, app in apps.items():
        vercode = 0
        if ':' in app_id:
            vercode = app_id.split(':')[1]
        for build in reversed(app.builds):
            if build.disable:
                continue
            if options.latest or vercode == 0 or build.versionCode == vercode:
                app.builds = [build]
                break
            continue
        continue

    for app_id, app in apps.items():
        for build in app.builds:
            apks = []
            for f in os.listdir(options.repo_path):
                n = common.get_release_filename(app, build)
                if f == n:
                    apks.append(f)
            for apk in sorted(apks):
                apk_path = os.path.join(options.repo_path, apk)
                docker.perform_drozer_scan(apk_path, app.id)

    if options.clean_after:
        docker.clean()


if __name__ == "__main__":
    main()

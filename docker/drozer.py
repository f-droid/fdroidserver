#!/usr/bin/env python2

import pexpect
import sys

prompt = "dz>"
target = sys.argv[1]

drozer = pexpect.spawn("drozer console connect")
drozer.logfile = open("/tmp/drozer_report.log", "w")


# start
drozer.expect(prompt)


def send_command(command, target):
    cmd = "run {0} -a {1}".format(command, target)
    drozer.sendline(cmd)
    drozer.expect(prompt)

scanners = [
    "scanner.misc.native",          # Find native components included in packages
    #"scanner.misc.readablefiles",   # Find world-readable files in the given folder
    #"scanner.misc.secretcodes",     # Search for secret codes that can be used from the dialer
    #"scanner.misc.sflagbinaries",   # Find suid/sgid binaries in the given folder (default is /system).
    #"scanner.misc.writablefiles",   # Find world-writable files in the given folder
    "scanner.provider.finduris",    # Search for content providers that can be queried.
    "scanner.provider.injection",   # Test content providers for SQL injection vulnerabilities.
    "scanner.provider.sqltables",   # Find tables accessible through SQL injection vulnerabilities.
    "scanner.provider.traversal"    # Test content providers for basic directory traversal
]

for scanner in scanners:
    send_command(scanner, target)

#!/usr/bin/env python2

import os
from subprocess import call, check_output
from time import sleep

FNULL = open(os.devnull, 'w')

print("Ensuring device is online")
call("adb wait-for-device", shell=True)

print("Installing the drozer agent")
print("If the device just came online it is likely the package manager hasn't booted.")
print("Will try multiple attempts to install.")
print("This may need tweaking depending on hardware.")


attempts = 0
time_to_sleep = 30

while attempts < 8:
    output = check_output('adb shell "pm list packages"', shell=True)
    print("Checking whether the package manager is up...")
    if "Could not access the Package Manager" in output:
        print("Nope. Sleeping for 30 seconds and then trying again.")
        sleep(time_to_sleep)
    else:
        break

time_to_sleep = 5
attempts = 0

while attempts < 5:
    sleep(time_to_sleep)
    try:
        install_output = check_output("adb install /home/drozer/drozer-agent.apk", shell=True)
    except Exception:
        print("Failed. Trying again.")
        attempts += 1
    else:
        attempts += 1
        if "Error: Could not access the Package Manager" not in install_output:
            break

print("Install attempted. Checking everything worked")

pm_list_output = check_output('adb shell "pm list packages"', shell=True)

if "com.mwr.dz" not in pm_list_output:
    print(install_output)
    exit("APK didn't install properly. Exiting.")

print("Installed ok.")

print("Starting the drozer agent main activity: com.mwr.dz/.activities.MainActivity")
call('adb shell "am start com.mwr.dz/.activities.MainActivity"', shell=True, stdout=FNULL)

print("Starting the service")
# start the service
call("python /home/drozer/enable_service.py", shell=True, stdout=FNULL)

print("Forward dem ports mon.")
call("adb forward tcp:31415 tcp:31415", shell=True, stdout=FNULL)

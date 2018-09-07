#!/usr/bin/env python3

import re


def test(packageName):
    m = ANDROID_APPLICATION_ID_REGEX.match(packageName.strip())
    return m is not None


ANDROID_APPLICATION_ID_REGEX = re.compile(r'''(?:^[a-z_]+(?:\d*[a-zA-Z_]*)*)(?:\.[a-z_]+(?:\d*[a-zA-Z_]*)*)*$''')
valid = 0
invalid = 0

test('org.fdroid.fdroid')
with open('valid.txt', encoding="utf-8") as fp:
    for packageName in fp:
        packageName = packageName.strip()
        if not test(packageName):
            valid += 1
            # print('should be valid:', packageName)

with open('invalid.txt', encoding="utf-8") as fp:
    for packageName in fp:
        packageName = packageName.strip()
        if test(packageName):
            invalid += 1
            print('should be not valid: "' + packageName + '"')


print(valid, 'Java thinks is valid, but the Android regex does not')
print(invalid, 'invalid mistakes')

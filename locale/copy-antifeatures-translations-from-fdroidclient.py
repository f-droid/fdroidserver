#!/usr/bin/env python3

# Remove extra translations

import glob
import os
import re
from xml.etree import ElementTree  # nosec B405

resdir = '../fdroidclient/app/src/main/res'

for d in sorted(glob.glob(os.path.join(resdir, 'values-*'))):
    str_path = os.path.join(d, 'strings.xml')
    if not os.path.exists(str_path):
        continue
    segments = os.path.dirname(str_path).split('-')
    if len(segments) == 1:
        continue
    elif len(segments) == 2:
        locale = segments[1]
    elif segments[2] == 'rCN':
        locale = f'{segments[1]}_Hans'
    elif segments[2] == 'rTW':
        locale = f'{segments[1]}_Hant'
    else:
        locale = f'{segments[1]}_{segments[2].lstrip("r")}'
    print(locale, segments)

    with open(str_path, encoding='utf-8') as fp:
        fulltext = fp.read()

    tree = ElementTree.parse(str_path)  # nosec B314
    root = tree.getroot()

    sources = {
        'antidisabledalgorithmlist': 'This app has a weak security signature',
        'antiknownvulnlist': 'This app contains a known security vulnerability',
    }
    for e in root.findall('.//string'):
        if e.text is None:
            continue
        name = e.attrib['name']
        if name not in ('antidisabledalgorithmlist', 'antiknownvulnlist'):
            continue
        f = f'locale/{locale}/LC_MESSAGES/fdroidserver.po'
        if not os.path.exists(f):
            continue
        print(sources[name], e.text)
        text = e.text.replace("\\'", "'")
        with open(f) as fp:
            source = re.sub(
                rf'''\nmsgid ("{sources[name]}")\nmsgstr "[^"]*"\n\n''',
                rf'''\nmsgid \1\nmsgstr "{text}"\n\n''',
                fp.read(),
            )
        with open(f, 'w') as fp:
            fp.write(source)
        print(f)

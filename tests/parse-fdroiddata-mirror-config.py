#!/usr/bin/env python3

import ruamel.yaml

from pathlib import Path

mirrors_yml = Path('/home/hans/code/fdroid/fdroiddata/config/mirrors.yml')
with mirrors_yml.open() as fp:
    mirrors_config = ruamel.yaml.YAML(typ='safe').load(fp)

for d in mirrors_config:
    d['url'] += '/repo'
    print(d, end=',\n')

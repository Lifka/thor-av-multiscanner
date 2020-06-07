# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera. <javierizquierdovera.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import ntpath
import subprocess
import re
import subprocess

def get_Docker_version():
    return exec('docker -v')

def is_docker_installed():
    return re.compile(r'version').search(get_Docker_version())

def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

def exec(command):
    return subprocess.check_output(command, shell=True).decode('utf-8')
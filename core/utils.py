# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera. <javierizquierdovera.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import ntpath
import subprocess
import re
import subprocess
import asyncio
import os

def get_Docker_version():
    return asyncio.run(exec('docker -v'))

def is_docker_installed():
    return re.compile(r'version').search(get_Docker_version())

def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

async def exec(command):
    proc = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await proc.communicate()
    return stdout.decode()

def is_a_valid_file(file):
    return os.path.isfile(file) and os.access(file, os.R_OK)
    
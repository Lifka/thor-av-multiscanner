# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera. <javierizquierdovera.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import subprocess
import ntpath
from core.utils import path_leaf, exec

async def scan_file_async(file_path, docker_configuration, loop):
    file_name = path_leaf(file_path)
    results = []
    for antivirus in docker_configuration:
        results.append(loop.create_task(run_docker_command(antivirus['scan_command'].format(file_path, file_name))))
    await asyncio.wait(results)
    return results

def list_available_antivirus(docker_configuration):
    result = []
    for antivirus in docker_configuration:
        result.append(antivirus['name'])
    return result



async def run_docker_command(command):
    return await exec('docker run {0}'.format(command))
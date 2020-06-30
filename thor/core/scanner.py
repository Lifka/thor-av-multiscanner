# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera <javierizquierdovera.com>.
# This program is free software, you can redistribute it and/or modify it under the terms of GPLv2.

import asyncio
from core.utils import path_leaf, exec
from os.path import abspath
import json

DEFAULT_UPDATE_COMMAND = "{Image} update"
DEFAULT_SCAN_COMMAND = "--rm -v \"{File_path}:/malware/{File_name}\" {Image} {File_name}"
DEFAULT_PULL_COMMAND = "docker pull {Image}"

async def scan_file_async(file_path, docker_configuration, loop):
    absolute_file_path = abspath(file_path)
    file_name = path_leaf(file_path)
    tasks = responses = {}
    for antivirus in docker_configuration:
        if 'scan_command' not in antivirus:
            antivirus['scan_command'] = DEFAULT_SCAN_COMMAND
        tasks[antivirus['name']] = loop.create_task(run_docker_command(antivirus['scan_command'].format(File_path=absolute_file_path, File_name=file_name, Image=antivirus['image'])))
    for av_name, task in tasks.items():
        responses[av_name] = await asyncio.gather(task)
    return responses

def scan_file_parse_results(results):
    responses = {}
    for av_name, result in results.items():
        if len(result) > 0 and result[0]:
            responses[av_name] = json.loads(result[0])
            responses[av_name] = responses[av_name][list(responses[av_name].keys())[0]]
    return responses
    
def list_available_antivirus(docker_configuration):
    result = []
    for antivirus in docker_configuration:
        result.append(antivirus['name'])
    return result

async def update_antivirus_async(docker_configuration, loop):
    tasks = []
    for antivirus in docker_configuration:
        if 'update_command' not in antivirus:
            antivirus['update_command'] = DEFAULT_UPDATE_COMMAND
        tasks.append(loop.create_task(run_docker_command(antivirus['update_command'].format(Image=antivirus['image']))))
    return await asyncio.gather(*tasks)

async def pull_dockers_async(docker_configuration, loop):
    tasks = []
    for antivirus in docker_configuration:
        if 'pull_command' not in antivirus:
            antivirus['pull_command'] = DEFAULT_PULL_COMMAND
        tasks.append(loop.create_task(run_docker_command(antivirus['pull_command'].format(Image=antivirus['image']))))
    return await asyncio.gather(*tasks)

async def run_docker_command(command):
    return await exec('docker run {0}'.format(command))
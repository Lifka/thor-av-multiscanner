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
DEFAULT_LICENSE_COMMAND = "-v {License}"

async def scan_file_async(file_path, docker_configuration):
    return await get_run_operation_result_by_av('scan_command', DEFAULT_SCAN_COMMAND, docker_configuration, abspath(file_path), path_leaf(file_path))

async def update_antivirus_async(docker_configuration):
    return await get_run_operation_result_by_av('docker_configuration', DEFAULT_UPDATE_COMMAND, docker_configuration)

async def pull_dockers_async(docker_configuration):
    tasks = responses = {}
    for antivirus in docker_configuration:
        tasks[antivirus['name']] = asyncio.get_event_loop().create_task(pull_docker_image(antivirus['image']))
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

async def get_run_operation_result_by_av(operation, default_value, docker_configuration, file_path='', file_name=''):
    tasks = responses = {}
    for antivirus in docker_configuration:
        command = license = ''
        if 'license' in  antivirus and operation == 'scan_command':
            license = antivirus['license']
            command += '{} '.format(antivirus['license_command']) if 'license_command' in antivirus else  '{} '.format(DEFAULT_LICENSE_COMMAND)
        command += '{}'.format(default_value) if operation not in antivirus else '{}'.format(antivirus[operation])
        tasks[antivirus['name']] = asyncio.get_event_loop().create_task(run_docker_command(command.format(Image=antivirus['image'], File_path=file_path, File_name=file_name, License=license)))
    for av_name, task in tasks.items():
        responses[av_name] = await asyncio.gather(task)
    return responses

async def run_docker_command(command):
    return await exec('docker run {0}'.format(command))

async def pull_docker_image(image):
    return await exec('docker pull {0}'.format(image))
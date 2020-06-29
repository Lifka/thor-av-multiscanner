# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera <javierizquierdovera.com>.
# This program is free software, you can redistribute it and/or modify it under the terms of GPLv2.

import asyncio
from core.utils import path_leaf, exec
from os.path import abspath
import json

async def scan_file_async(file_path, docker_configuration, loop):
    absolute_file_path = abspath(file_path)
    file_name = path_leaf(file_path)
    tasks = responses = {}
    for antivirus in docker_configuration:
        tasks[antivirus['name']] = loop.create_task(run_docker_command(antivirus['scan_command'].format(File_path=absolute_file_path, File_name=file_name)))
    for av_name, task in tasks.items():
        responses[av_name] = await asyncio.gather(task)
    return responses

def scan_file_parse_results(results):
    responses = {}
    for av_name, result in results.items():
        if len(result) > 0:
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
        tasks.append(loop.create_task(run_docker_command(antivirus['update_command'])))
    return await asyncio.gather(*tasks)

async def run_docker_command(command):
    return await exec('docker run {0}'.format(command))
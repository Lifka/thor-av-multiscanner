# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera <javierizquierdovera.com>.
# This program is free software, you can redistribute it and/or modify it under the terms of GPLv2.

import asyncio
from core import scanner, file_info, strings
from core.utils import is_docker_installed, is_a_valid_file, is_docker_configuration_available, get_docker_configuration

async def scan_file(file_path, config):
    return await scanner.scan_file_async(file_path, get_docker_configuration(config), asyncio.get_event_loop())

def get_file_info(file_path):
    return file_info.get_file_info_json(file_path)

async def get_file_strings(file_path, separator='[SEPARATOR]'):
    return await strings.get_strings_json(file_path, separator)
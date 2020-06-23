# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera. <javierizquierdovera.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
from core import scanner
from core.utils import is_docker_installed, is_a_valid_file, is_docker_configuration_available, get_docker_configuration

DOCKER_CONFIG_PATH = "docker_configuration.json"

async def scan_file(file):
    loop = asyncio.get_event_loop()
    result = await scanner.scan_file_async(file, get_docker_configuration(DOCKER_CONFIG_PATH), loop)
    return result
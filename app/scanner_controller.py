# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera <javierizquierdovera.com>.
# This program is free software, you can redistribute it and/or modify it under the terms of GPLv2.

import asyncio
from core import scanner, file_info, strings, imports, PE_analyser
from core.utils import is_docker_installed, is_a_valid_file, is_docker_configuration_available, get_docker_configuration

async def scan_file(file_path, config):
    scan_result = await scanner.scan_file_async(file_path, get_docker_configuration(config))
    return scanner.scan_file_parse_results(scan_result)

def get_file_info(file_path):
    return file_info.get_file_info_json(file_path)

async def get_file_strings(file_path, separator='[SEPARATOR]'):
    return await strings.get_strings_json(file_path, separator)

async def get_imported_dlls(file_path):
    return await imports.get_imported_dlls_json(file_path)

def get_pe_info(file_path):
    return PE_analyser.get_pe_info_json(file_path)
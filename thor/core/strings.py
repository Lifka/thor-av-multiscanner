# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera <javierizquierdovera.com>.
# This program is free software, you can redistribute it and/or modify it under the terms of GPLv2.

from core.utils import exec
import json

DEFAULT_SEPARATOR = '[SEPARATOR]'

async def get_strings(file_path, separator=DEFAULT_SEPARATOR):
    strings = await run_strings_command({ '-s': separator, '': file_path, '--all': '' })
    return strings.split(separator)

async def get_strings_json(file_path, separator=DEFAULT_SEPARATOR):
    response = await get_strings(file_path)
    return json.dumps({ "strings": response })

async def run_strings_command(parameters={}):
    parse_parameters = ''
    for param, value in parameters.items():
        parse_parameters += '{} '.format(param) if not value else '{} "{}" '.format(param, value)
    return await exec('strings {}'.format(parse_parameters))
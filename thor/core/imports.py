# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera <javierizquierdovera.com>.
# This program is free software, you can redistribute it and/or modify it under the terms of GPLv2.

from core.strings import get_strings
import json

async def get_imported_dlls(file_path):
    strings = await get_strings(file_path)
    dlls = list(filter(lambda string: '.dll' in string, strings))
    marker = set()
    return [not marker.add(dll.casefold()) and dll for dll in dlls if dll.casefold() not in marker]

async def get_imported_dlls_json(file_path):
    response = await get_imported_dlls(file_path)
    return json.dumps({ "imported_dlls": response })

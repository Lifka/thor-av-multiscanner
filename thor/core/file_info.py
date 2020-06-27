# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera <javierizquierdovera.com>.
# This program is free software, you can redistribute it and/or modify it under the terms of GPLv2.

import json, os, hashlib
import core.magic_number as fleep

def get_file_info(path):
    result = {}
    
    size, unit = get_pretty_size(path)
    result['size'] = { 'size': size, 'unit': unit }

    result['hashes'] = { 'MD5': '{}'.format(md5(path)) , 'SHA-1': '{}'.format(sha1(path)), 'SHA-256': '{}'.format(sha256(path)) }

    format_type, format_extension, format_mime = get_info_from_magic_number(path)
    result['format'] = { 'type': format_type, 'extension': format_extension, 'mime': format_mime }

    return result

def get_file_info_json(path):
    return json.dumps(get_file_info(path))

def get_pretty_size(path):
    size = os.stat(path).st_size
    pretty_size = size
    unit = 'B'
    GB = 1073741824 #1024*1024*1024
    MB = 1048576 #1024*1024
    KB = 1024 #1024
    if (size > GB):
        pretty_size = round(size/GB, 3)
        unit = 'GB'
    elif (size > MB):
        pretty_size = round(size/MB, 3)
        unit = 'MB'
    elif (size > KB):
        pretty_size = round(size/KB, 3)
        unit = 'KB'
    return pretty_size, unit

def md5(path):
    return get_file_hash(path, hashlib.md5())

def sha1(path):
    return get_file_hash(path, hashlib.sha1())

def sha256(path):
    return get_file_hash(path, hashlib.sha256())

def get_file_hash(path, hash_function):
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_function.update(chunk)
    return hash_function.hexdigest().lower()

def get_info_from_magic_number(path):
    with open(path, "rb") as file:
        result = fleep.get(file.read(128))

    return result.type, result.extension, result.mime
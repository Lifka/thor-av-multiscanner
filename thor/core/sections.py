# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera <javierizquierdovera.com>.
# This program is free software, you can redistribute it and/or modify it under the terms of GPLv2.

import json
import pefile

def get_section_name(section_raw_name):
    try:
        section_name = str(section_raw_name, 'utf-8').encode('ascii', errors='ignore').strip().decode('ascii').strip(' \t\r\n\0')
    except:
        section_name = str(section_raw_name, 'ISO-8859-1').encode('ascii', errors='ignore').strip().decode('ascii').strip(' \t\r\n\0')
    if section_name == '':
        section_name = '.noname'
    return section_name

def get_section_data(section):
    section_data = {}
    section_data['virtual_address'] = section.VirtualAddress
    section_data['virtual_size'] = section.Misc_VirtualSize
    section_data['raw_size'] = section.SizeOfRawData
    section_data['characteristics'] = section.Characteristics
    section_data['hashes'] = { 'MD5' : section.get_hash_md5(), 'SHA-1' : section.get_hash_sha1(), 'SHA-256' : section.get_hash_sha256() }
    section_data['entropy'] = round(section.get_entropy(), 3)
    return section_data

def get_sections(file_path):
    return { get_section_name(section.Name):get_section_data(section) for section in pefile.PE(file_path).sections }

def get_sections_json(file_path):
    return json.dumps({ "sections": get_sections(file_path) })
 
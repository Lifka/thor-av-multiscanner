# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera <javierizquierdovera.com>.
# This program is free software, you can redistribute it and/or modify it under the terms of GPLv2.

import json
import pefile
import datetime

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

def get_entry_point(pe):
    return pe.OPTIONAL_HEADER.AddressOfEntryPoint

MACHINE_CODES = {
    332: 'Intel 386 or later processors and compatible processors'
}

def get_target_machine(pe):
    return '' if not pe.FILE_HEADER.Machine in MACHINE_CODES else MACHINE_CODES[pe.FILE_HEADER.Machine]

def get_compilation_timestamp(pe):
    return datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S')

def get_sections(file_path, pe):
    return { get_section_name(section.Name):get_section_data(section) for section in pe.sections }

def get_pe_info_json(file_path):
    sections, entry_point, target_machine, compilation_timestamp = get_pe_info(file_path)
    return json.dumps({ "sections": sections, "entry_point": entry_point, "target_machine": target_machine, "compilation_timestamp": compilation_timestamp})
 
def get_pe_info(file_path):
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        return {} # DOS Header magic not found.
    return get_sections(file_path, pe), get_entry_point(pe), get_target_machine(pe), get_compilation_timestamp(pe)
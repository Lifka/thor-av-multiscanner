# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera. <javierizquierdovera.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import subprocess
import ntpath
from core.utils import path_leaf, exec

def scan_file(file_path):
    file_name = path_leaf(file_path)
    scan_file_with_avg(file_path, file_name)

def scan_file_with_avg(file_path, file_name):
    command = 'docker run --rm -v "{0}:/malware/malware.exe" malice/avg {1}'.format(file_path, file_name)
    result = exec(command)
    print(result)

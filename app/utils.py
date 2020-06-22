# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera. <javierizquierdovera.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os, hashlib, datetime
from werkzeug.utils import secure_filename

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest().upper()

def get_file_by_hash(hash, path):
    hash = hash.upper()
    return [f for f in os.listdir(path) if md5(os.path.join(path, f)) == hash]

def save_file(file, vault):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = "{}__{}".format(timestamp, secure_filename(file.filename))
    path = os.path.join(vault, filename)
    file.save(path)
    return path
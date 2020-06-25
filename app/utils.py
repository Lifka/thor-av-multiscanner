# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera. <javierizquierdovera.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os, hashlib, datetime
from werkzeug.utils import secure_filename

def get_file_hash(path):
    hash_algo = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_algo.update(chunk)
    return hash_algo.hexdigest().lower()


def get_file_by_hash_in_dir(hash, path):
    hash = hash.lower()
    return [f for f in os.listdir(path) if get_file_hash(os.path.join(path, f)) == hash]

def save_file(file, vault):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = "{}__{}".format(timestamp, secure_filename(file.filename))
    path = os.path.join(vault, filename)
    file.save(path)
    return path
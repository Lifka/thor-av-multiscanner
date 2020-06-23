# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera. <javierizquierdovera.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from utils import get_file_by_hash, save_file, md5
import json

import asyncio
from functools import wraps
from scanner_wrapper import scan_file

from quart import Quart, render_template, request

VAULT = "vault"

app = Quart(__name__)
app.config["VAULT"] = VAULT
app.config["files_by_hash"] = {}

@app.route('/')
async def home():
    return await render_template("home.html")

@app.route('/about', strict_slashes=False)
async def about():
    return await render_template("about.html")

@app.route('/upload-file', methods=["POST"])
async def upload_file():
    if request.method != 'POST':
        return json.dumps({"status": "error", "message": "No POST request"})

    files = await request.files
    if 'file' not in files:
        return json.dumps({"status": "error", "message": "Incorrect request. It was expected to receive the file using POST."})
    file = files["file"] 
    if not file.filename:
        return json.dumps({"status": "error", "message": "Empty file."})

    file_path = save_file(file, app.config["VAULT"])
    print("[upload_file] Sent file -> {}: {}".format(file_path, file))
    return json.dumps({"status": "success", "hash":'{}'.format(md5(file_path))})

@app.route('/file-analysis/<hash>')
async def file_analysis(hash):
    files = get_file_by_hash(hash, app.config["VAULT"])
    if not files:
        print("[file_analysis] No file(s) found for hash -> {}".format(hash))
        return home()
    print("[file_analysis] Get results from -> {}".format(files))
    app.config["files_by_hash"][hash] = files[0]
    return await render_template("scan-results.html")

@app.route('/file-analysis/<hash>/result', methods=["POST"])
async def file_analysis_result(hash):
    if hash not in app.config["files_by_hash"]:
        app.config["files_by_hash"][hash] = get_file_by_hash(hash)
    print('file_analysis_result from -> {}'.format(app.config["files_by_hash"][hash]))
    result = scan_file(app.config["files_by_hash"][hash])

    return await result

if __name__ == '__main__':
    app.run(debug=True)
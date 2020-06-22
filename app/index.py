# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera. <javierizquierdovera.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from flask import Flask, render_template, request
from utils import get_file_by_hash, save_file, md5
import json

import asyncio
from functools import wraps
from scanner_wrapper import scan_file

VAULT = "vault"

app = Flask(__name__)
app.config["VAULT"] = VAULT
app.config["files_by_hash"] = {}

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/about', strict_slashes=False)
def about():
    return render_template("about.html")
       
@app.route('/upload-file', methods=["POST"])
def upload_file():
    if request.method != 'POST':
        return json.dumps({"result": "error", "message": "No POST request"})

    if 'file' not in request.files:
        return json.dumps({"result": "error", "message": "Upload error"})

    file = request.files["file"] 
    if not file.filename:
        return json.dumps({"result": "error", "message": "Empty file"})

    file_path = save_file(file, app.config["VAULT"])
    print("[upload_file] Sent file -> {}: {}".format(file_path, file))
    return json.dumps({"result": "success", "hash":'{}'.format(md5(file_path))})

@app.route('/file-analysis/<hash>')
def file_analysis(hash):
    files = get_file_by_hash(hash, app.config["VAULT"])
    if not files:
        print("[file_analysis] No file(s) found for hash -> {}".format(hash))
        return home()
    print("[file_analysis] Get results from -> {}".format(files))
    app.config["files_by_hash"][hash] = files[0]
    return render_template("scan-results.html")

def async_action(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))
    return wrapped

@app.route('/file-analysis/<hash>/result', methods=["POST"])
@async_action
async def file_analysis_result(hash):
    if hash not in app.config["files_by_hash"]:
        app.config["files_by_hash"][hash] = get_file_by_hash(hash)
    print('file_analysis_result from -> {}'.format(app.config["files_by_hash"][hash]))
    result = scan_file(app.config["files_by_hash"][hash])

    return result

if __name__ == '__main__':
    app.run(debug=True)
# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera. <javierizquierdovera.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from flask import Flask, render_template, request
from utils import get_file_by_hash, save_file

import asyncio
from functools import wraps
from scanner_wrapper import scan_file

VAULT = "vault"

app = Flask(__name__)
app.config["VAULT"] = VAULT

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/about', strict_slashes=False)
def about():
    return render_template("about.html")
       
@app.route('/file-upload', methods=["POST"])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            print("[upload_file] Upload error")
            return home()

        file = request.files["file"] 
        if not file.filename:
            print("[upload_file] Empty file")
            return home()

        file_path = save_file(file, app.config["VAULT"])
        print("[upload_file] Sent file -> {}: {}".format(file_path, file))
    return home()

@app.route('/file-analysis/<hash>')
def file_analysis(hash):
    files = get_file_by_hash(hash, app.config["VAULT"])
    if not files:
        return home()
    print("[file_analysis] Get results from -> {}".format(files))
    return render_template("scan-results.html")

def async_action(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))
    return wrapped

@app.route('/file-analysis/<hash>/result', methods=["POST"])
@async_action
async def file_analysis_result(hash):
    result = scan_file(get_file_by_hash(hash, app.config["VAULT"])[0])

    return result

if __name__ == '__main__':
    app.run(debug=True)
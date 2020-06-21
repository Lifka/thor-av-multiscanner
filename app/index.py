# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera. <javierizquierdovera.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os, datetime
import hashlib
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
import asyncio
from core import scanner
from core.utils import is_docker_installed, is_a_valid_file, is_docker_configuration_available, get_docker_configuration

VAULT = "vault"
DOCKER_CONFIG_PATH = "docker_configuration.json"

app = Flask(__name__)
app.config["VAULT"] = VAULT
app.config["DOCKER_CONFIG_PATH"] = DOCKER_CONFIG_PATH

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/about', strict_slashes=False)
def about():
    return render_template("about.html")

def save_file(file):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = "{}__{}".format(timestamp, secure_filename(file.filename))
    path = os.path.join(app.config["VAULT"], filename)
    file.save(path)
    return path
       
@app.route('/file-upload', methods=["POST"])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            print("Upload error")
            return home()

        file = request.files["file"] 

        if not file.filename:
            print("Empty file")
            return home()

        file_path = save_file(file)
        print("Sent file --> {}: {}".format(file_path, file))

    return home()


def scan_file(file_path):
    loop = asyncio.get_event_loop()
    result = loop.run_until_complete(scanner.scan_file_async(file_path, get_docker_configuration(DOCKER_CONFIG_PATH), loop))
    loop.close()
    return result

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

@app.route('/file-analysis/<hash>')
def file_analysis(hash):
    #return send_from_directory(app.config['VAULT'], filename)
    #result = scan_file(file_path)
    #print("OK {}: {}".format(file_path, result))
    
    files = [f for f in os.listdir(app.config["VAULT"]) if md5(os.path.join(app.config["VAULT"], f)) == hash]
    if not files:
        return home()

    print("Get result --> {}".format(files))
    return render_template("scan-results.html")

if __name__ == '__main__':
    app.run(debug=True)
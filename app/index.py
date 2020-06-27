# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera. <javierizquierdovera.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from utils import get_file_by_hash_in_dir, save_file, get_file_hash
import json, os
from os.path import abspath

from quart import Quart, render_template, request
from scanner_wrapper import scan_file, get_file_info

VAULT = "vault"
DOCKER_CONFIG_PATH = "docker_configuration.json"

app = Quart(__name__)
app.config["VAULT"] = VAULT
app.config["DOCKER_CONFIG_PATH"] = DOCKER_CONFIG_PATH
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
    return json.dumps({"status": "success", "hash":'{}'.format(get_file_hash(file_path))})

@app.route('/file-analysis/<hash>')
async def file_analysis(hash):
    files = get_file_by_hash_in_dir(hash, app.config["VAULT"])
    if not files:
        print("[file_analysis] No file(s) found for hash -> {}".format(hash))
        return home()
    print("[file_analysis] Get results from -> {}".format(files))
    app.config["files_by_hash"][hash] = abspath(os.path.join(app.config["VAULT"], files[0]))
    return await render_template("scan-results.html")

def get_file(hash):
    if hash not in app.config["files_by_hash"]:
        app.config["files_by_hash"][hash] = abspath(os.path.join(app.config["VAULT"], get_file_by_hash_in_dir(hash, app.config["VAULT"])))
    return app.config["files_by_hash"][hash]


@app.route('/file-analysis/<hash>/detection', methods=["POST"])
async def file_analysis_result(hash):
    table_html_scan_results = ''
    error_message = ''
    try:
        analysis = scan_file(get_file(hash), app.config["DOCKER_CONFIG_PATH"])
        result = await analysis
        table_html_scan_results = await parse_analysis_results(result)
        status = 'success'
    except Exception as e:
        error_message = 'Error receiving data from the scanner. Error: {}'.format(str(e))
        status = 'error'

    return json.dumps({"status": '{}'.format(status), "table_html_scan_results":'{}'.format(table_html_scan_results), "error_message":'{}'.format(error_message)})

async def parse_analysis_results(results):
    result_html = '<table class="table table-striped"><tbody>'
    for av_result in results:
        av_result_object = json.loads(av_result)
        av_name = list(av_result_object.keys())[0]
        av_result = av_result_object[av_name]
        if av_result['infected']:
            result_html += "<tr><td class='av_name'>{}</td><td class='av_result infected'><i class='fas fa-exclamation-circle icon-infected'></i>{}</td>".format(av_name, av_result['result'])
        else:
            result_html += "<tr><td class='av_name'>{}</td><td class='av_result'><i class='far fa-check-circle icon-clean'></i>Undetected".format(av_name)
    result_html += '</tbody></table>'
    return result_html

@app.route('/file-analysis/<hash>/info', methods=["POST"])
async def file_analysis_info(hash):
    html_file_info = ''
    error_message = ''

    file = get_file(hash)
    try:
        name = ''.join(file.split('_')[2:])
        status = 'success'
        html_file_info = json.loads(get_file_info_json(file))
    except Exception as e:
        error_message = 'File error: {}'.format(str(e))
        status = 'error'
        
    return json.dumps({"status": '{}'.format(status), "html_file_info":'{}'.format(html_file_info), "error_message":'{}'.format(error_message)})


if __name__ == '__main__':
    app.run(debug=True)
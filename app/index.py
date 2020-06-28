# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera <javierizquierdovera.com>.
# This program is free software, you can redistribute it and/or modify it under the terms of GPLv2.

from utils import get_file_by_hash_in_dir, save_file, get_file_hash, get_current_date
import json, os
from os.path import abspath

from quart import Quart, render_template, request
from scanner_wrapper import scan_file, get_file_info, get_file_strings

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
    if hash not in app.config["files_by_hash"]:
        app.config["files_by_hash"][hash] = {}
    app.config["files_by_hash"][hash]['file'] = abspath(os.path.join(app.config["VAULT"], files[0]))
    return await render_template("scan-results.html")

@app.route('/file-analysis/<hash>/detection', methods=["POST"])
async def file_analysis_result(hash):
    async def get_analysis_result_response(file):
        analysis_coroutine = scan_file(get_file(hash), app.config["DOCKER_CONFIG_PATH"])
        analysis_response = await analysis_coroutine
        table_html_scan_results, av_count, infected_count, icon = parse_analysis_result(analysis_response)
        scan_date = get_current_date()
        print(scan_date)
        scan_date_string = "{} {}".format(scan_date[0], scan_date[1].replace('-', ':'))
        return { "table_html_scan_results": table_html_scan_results, "av_count": av_count, "infected_count": infected_count, "icon": icon, "scan_date": scan_date_string}
    response = await exec_with_cache(hash, 'detection', get_analysis_result_response, (get_file(hash),), True)
    return json.dumps(response)

@app.route('/file-analysis/<hash>/info', methods=["POST"])
async def file_analysis_info(hash):
    def get_file_info_response(file):
        file_name = ''.join(file.split('_')[2:])
        file_info = json.loads(get_file_info(file))
        table_html_file_info = parse_analysis_info(file_info, file_name)
        return { 'table_html_file_info': table_html_file_info }
    response = await exec_with_cache(hash, 'info', get_file_info_response, (get_file(hash),))
    return json.dumps(response,)

@app.route('/file-analysis/<hash>/strings', methods=["POST"])
async def file_analysis_strings(hash):
    async def get_strings_response(file):
        strings_coroutine = get_file_strings(file)
        strings_response = await strings_coroutine
        strings = json.loads(strings_response)['strings']
        count = len(strings)
        table_html_strings = parse_file_analysis_strings_result(strings)
        return { 'table_html_strings':table_html_strings, "count": count }
    response = await exec_with_cache(hash, 'strings', get_strings_response, (get_file(hash),), True)
    return json.dumps(response)

@app.route('/file-analysis/<hash>/clean-cache', methods=["POST"])
async def file_analysis_clean_cache(hash):
    def clean_cache(hash):
        app.config["files_by_hash"].pop(hash, None)
        return {}
    response = await exec(clean_cache, (hash,))
    return json.dumps(response)

async def exec_with_cache(hash, operation, my_function, my_args, coroutine=False):
    response = app.config["files_by_hash"][hash][operation] if operation in app.config["files_by_hash"][hash] else await exec(my_function, my_args, coroutine)
    app.config["files_by_hash"][hash][operation] = response
    return app.config["files_by_hash"][hash][operation]

async def exec(my_function, my_args, coroutine=False):
    result = error_message = satus = ''
    try:
        result, status = await my_function(*my_args) if coroutine else my_function(*my_args), 'success'
    except Exception as e:
        error_message, status = '{}'.format(str(e)), 'error'
    return { "status": status, "result": result, "error_message": error_message }

def get_file(hash):
    if hash not in app.config["files_by_hash"]:
        app.config["files_by_hash"][hash] = {}
        app.config["files_by_hash"][hash]['file'] = abspath(os.path.join(app.config["VAULT"], get_file_by_hash_in_dir(hash, app.config["VAULT"])[0]))
    return app.config["files_by_hash"][hash]['file']

def parse_analysis_info(file_info, file_name):
    result_html = '<table class="table table-striped"><tbody>'
    result_html += '<tr><td>Name</td><td>{}</td>'.format(file_name)
    result_html += '<tr><td>Size</td><td>{} {}</td>'.format(file_info['size']['size'], file_info['size']['unit'])
    result_html += '<tr><td>MD5</td><td><small><i>{}</i></small></td>'.format(file_info['hashes']['MD5'])
    result_html += '<tr><td>SHA-1</td><td><small><i>{}</i></small></td>'.format(file_info['hashes']['SHA-1'])
    result_html += '<tr><td>SHA-256</td><td><small><i>{}</i></small></td>'.format(file_info['hashes']['SHA-256'])
    result_html += '<tr><td>Extension</td><td>{}</td>'.format(file_info['magic_number']['extension'][0])
    result_html += '<tr><td>Mime</td><td>{}</td>'.format(file_info['magic_number']['mime'][0])
    result_html += '<tr><td>File type</td><td>{}</td>'.format(file_info['magic_number']['type'][0])
    result_html += '</tbody></table>'
    return result_html

def parse_analysis_result(results):
    result_html = '<table class="table table-striped"><tbody>'
    av_count = 0
    infected_count = 0
    for av_result in results:
        av_result_object = json.loads(av_result)
        av_name = list(av_result_object.keys())[0]
        av_result = av_result_object[av_name]
        av_count += 1
        if av_result['infected']:
            infected_count += 1
            result_html += "<tr><td class='av_name'>{}</td><td class='av_result infected'><i class='fas fa-exclamation-circle icon-infected'></i>{}</td>".format(av_name, av_result['result'])
        else:
            result_html += "<tr><td class='av_name'>{}</td><td class='av_result'><i class='far fa-check-circle icon-clean'></i>Undetected".format(av_name)
    result_html += '</tbody></table>'
    icon = "<i class='fas fa-exclamation-circle icon-infected'></i>" if infected_count > 0 else "<i class='far fa-check-circle icon-clean'></i>"
    return result_html, av_count, infected_count, icon

def parse_file_analysis_strings_result(result):
    result_html = '<table class="table table-striped"><tbody>'
    count = 1
    for string in result:
        result_html += "<tr><th scope='row'>{}</th><td class='string'>{}</td>".format(count, string)
        count += 1
    result_html += '</tbody></table>'
    return result_html

if __name__ == '__main__':
    app.run(debug=True)
# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera <javierizquierdovera.com>.
# This program is free software, you can redistribute it and/or modify it under the terms of GPLv2.

from utils import get_file_by_hash_in_dir, save_file, get_file_hash, get_current_date
import json, os
from os.path import abspath

from quart import Quart, render_template, request
from scanner_wrapper import scan_file, get_file_info, get_file_strings, get_file_imports, get_pe_info

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
        if 'scan_date' not in app.config["files_by_hash"][hash]:
            scan_date = get_current_date()
            app.config["files_by_hash"][hash]['scan_date'] = "{} {}".format(scan_date[0], scan_date[1].replace('-', ':')) 
        scan_date_string = app.config["files_by_hash"][hash]['scan_date'] 
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

@app.route('/file-analysis/<hash>/imports', methods=["POST"])
async def file_analysis_imports(hash):
    async def get_imports_response(file):
        imports_coroutine = get_file_imports(file)
        imports_response = await imports_coroutine
        imports = json.loads(imports_response)['imports']
        count = len(imports)
        table_html_imports = parse_file_analysis_imports_result(imports)
        return { 'table_html_imports':table_html_imports, "count": count }
    response = await exec_with_cache(hash, 'imports', get_imports_response, (get_file(hash),), True)
    return json.dumps(response)

@app.route('/file-analysis/<hash>/pe-info', methods=["POST"])
async def file_analysis_pe_info(hash):
    def get_pe_info_response(file):
        response = get_pe_info(file)
        pe_info = json.loads(response)
        sections = pe_info['sections']
        entry_point, target_machine, compilation_timestamp = pe_info['entry_point'], pe_info['target_machine'], pe_info['compilation_timestamp'],
        section_count = len(sections)
        table_html_sections = parse_file_analysis_sections_result(sections)
        table_html_pe_info = parse_file_analysis_pe_info_result(entry_point, target_machine, compilation_timestamp)
        return { 'table_html_sections':table_html_sections, "section_count": section_count, "table_html_pe_info": table_html_pe_info}
    response = await exec_with_cache(hash, 'pe-info', get_pe_info_response, (get_file(hash),))
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
    result_html += '<tr><td>Name</td><td>{}</td></tr>'.format(file_name)
    result_html += '<tr><td>Size</td><td>{} {}</td></tr>'.format(file_info['size']['size'], file_info['size']['unit'])
    result_html += '<tr><td>MD5</td><td><small><i>{}</i></small></td></tr>'.format(file_info['hashes']['MD5'])
    result_html += '<tr><td>SHA-1</td><td><small><i>{}</i></small></td></tr>'.format(file_info['hashes']['SHA-1'])
    result_html += '<tr><td>SHA-256</td><td><small><i>{}</i></small></td></tr>'.format(file_info['hashes']['SHA-256'])
    if len(file_info['magic_number']['extension']) > 0:
        result_html += '<tr><td>Extension</td><td>{}</td></tr>'.format(file_info['magic_number']['extension'][0])
    if len(file_info['magic_number']['mime']) > 0:
        result_html += '<tr><td>Mime</td><td>{}</td></tr>'.format(file_info['magic_number']['mime'][0])
    if len(file_info['magic_number']['type']) > 0:
        result_html += '<tr><td>File type</td><td>{}</td></tr>'.format(file_info['magic_number']['type'][0])
    result_html += '</tbody></table>'
    return result_html

def parse_analysis_result(results):
    result_html = '<table class="table table-striped"><tbody>'
    av_count = 0
    infected_count = 0
    for av_name, av_result in results.items():
        av_count += 1
        if av_result['infected']:
            infected_count += 1
            result_html += "<tr><td class='av_name'>{}</td><td class='av_result infected'><i class='fas fa-exclamation-circle icon-infected'></i>{}</td></tr>".format(av_name, av_result['result'])
        else:
            result_html += "<tr><td class='av_name'>{}</td><td class='av_result'><i class='far fa-check-circle icon-clean'></i>Undetected</td></tr>".format(av_name)
    result_html += '</tbody></table>'
    icon = "<i class='fas fa-exclamation-circle icon-infected'></i>" if infected_count > 0 else "<i class='far fa-check-circle icon-clean'></i>"
    return result_html, av_count, infected_count, icon

def parse_file_analysis_strings_result(results):
    return parse_standard_table(results, 'string')

def parse_file_analysis_imports_result(results):
    return parse_standard_table(results, 'import')

def parse_file_analysis_pe_info_result(entry_point, target_machine, compilation_timestamp):
    if not entry_point and not target_machine and not compilation_timestamp:
        return 'This file does not comply with the Portable Executable format.'
    result_html = '<table class="table table-striped"><tbody>'
    if target_machine: 
        result_html += '<tr><td>Target Machine</td><td>{}</td></tr>'.format(target_machine)
    result_html += '<tr><td>Compilation Timestamp</td><td>{}</td></tr>'.format(compilation_timestamp)
    result_html += '<tr><td>Entry Point</td><td>{}</td></tr>'.format(entry_point)
    result_html += '</tbody></table>'
    return result_html

def parse_file_analysis_sections_result(results):
    if len(results) == 0:
        return ''
    header = [ 'Name', 'Virtual Address', 'Virtual Size', 'Raw Size', 'Entropy', 'MD5', 'SHA-1', 'SHA-256' ]
    result_html = '<table class="table table-striped">'
    result_html += '<thead><tr>'
    for column in header:
        result_html += '<th scope="col">{}</th>'.format(column)
    result_html += '</tr></thead>'
    result_html += '<tbody>'
    for section, section_data in results.items():
        result_html += "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><small>{}</small></td><td><small>{}</small></td><td><small>{}</small></td></tr>".format(section, section_data['virtual_address'], section_data['virtual_size'], section_data['raw_size'], section_data['entropy'], section_data['hashes']['MD5'], section_data['hashes']['SHA-1'], section_data['hashes']['SHA-256'])
    result_html += '</tbody>'
    result_html += '</table>'
    return result_html

def parse_standard_table(results, item_class):
    result_html = '<table class="table table-striped"><tbody>'
    count = 1
    for item in results:
        result_html += "<tr><th scope='row'>{}</th><td class='{}'>{}</td></tr>".format(count, item_class, item)
        count += 1
    result_html += '</tbody></table>'
    return result_html

if __name__ == '__main__':
    app.run(debug=True)
# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera <javierizquierdovera.com>.
# This program is free software, you can redistribute it and/or modify it under the terms of GPLv2.

import logging, argparse, sys, os, asyncio
from core import scanner, file_info, strings, imports, PE_analyser
from core.utils import is_docker_installed, is_a_valid_file, is_docker_configuration_available, get_docker_configuration

DOCKER_CONFIG_PATH = 'docker_configuration.json'
loop = asyncio.get_event_loop()

def print_file_info(file, json=False):
    file_info_dict = file_info.get_file_info(file)
    sections, entry_point, target_machine, compilation_timestamp, imports_from_pe = PE_analyser.get_pe_info(file)
    imported_dll_list = loop.run_until_complete(imports.get_imported_dlls(file))
    if json:
        response = {}
        response['file_info'] = file_info_dict
        response['pe_info'] = { 'sections': sections , 'entry_point': entry_point , 'target_machine': target_machine, 'compilation_timestamp': compilation_timestamp }
        response['imported_dlls'] = imported_dll_list
        print(response)
    else:
        print_info(file_info_dict)
        if entry_point:
            print_pe_info(sections, entry_point, target_machine, compilation_timestamp)
        if len(import_list) > 0:
            print_imports(import_list)

def scan_file(file, json=False):
    detections = scanner.scan_file_parse_results(loop.run_until_complete(scanner.scan_file_async(file, get_docker_configuration(DOCKER_CONFIG_PATH))))
    if json:
        response = {}
        response['detections'] = detections
        print(response)
    else:
        print_detections(detections)

def list_available_antivirus(json=False):
    result = scanner.list_available_antivirus(get_docker_configuration(DOCKER_CONFIG_PATH))
    if json:
        print(result)
    else:
        print_av_list(result)

def pull_dockers(json=False):
    result = loop.run_until_complete(scanner.pull_dockers_async(get_docker_configuration(DOCKER_CONFIG_PATH)))
    if json:
        print(result)
    else:
        print_pull_dockers(result)

def update_antivirus(json=False):
    result = loop.run_until_complete(scanner.update_antivirus_async(get_docker_configuration(DOCKER_CONFIG_PATH)))
    if json:
        print(result)
    else:
        print_update(result)

def print_header(title):
    print('-----------{}----------'.format('-' * len(title)))
    print('           {}          '.format(title))
    print('-----------{}----------'.format('-' * len(title)))

def print_info(info):
    print_header('File info')
    print('Size: {} {}'.format(info['size']['size'], info['size']['unit']))
    print('MD5: {}\nSHA-1: {}\nSHA-256: {}'.format(info['hashes']['MD5'], info['hashes']['SHA-1'], info['hashes']['SHA-256']))
    if 'extension' in info['magic_number']:
        print('Extension: {}'.format(', '.join(map(str, info['magic_number']['extension']))))
    if 'mime' in info['magic_number']:
        print('Mime: {}'.format(', '.join(map(str, info['magic_number']['mime']))))
    if 'type' in info['magic_number']:
        print('File Type: {}'.format(', '.join(map(str, info['magic_number']['type']))))
    print('\n')

def print_pe_info(sections, entry_point, target_machine, compilation_timestamp):
    print_header('Portable Executable Info (PE)')
    if target_machine:
        print('Target Machine: {}'.format(target_machine))
    print('Compilation Timestamp: {}'.format(compilation_timestamp))
    print('Entry Point: {}'.format(entry_point))
    print('\nSECTIONS:\n')
    for name, section_info in sections.items():
        print(' {}:\n\tVirtual Address: {}\n\tVirtual Size: {}\n\tRaw Size: {}\n\tCharacteristics: {}\n\tEntropy: {}\n\tMD5: {}\n\tSHA-1: {}\n\tSHA-256: {}'.format(name, section_info['virtual_address'], section_info['virtual_size'], section_info['raw_size'], section_info['characteristics'], section_info['entropy'], section_info['hashes']['MD5'], section_info['hashes']['SHA-1'], section_info['hashes']['SHA-256']))
    print('\n')
    
def print_imports(imported_dlls):
    print_header('Imported DLLs')
    for import_value in imported_dlls:
        print(' - {}'.format(import_value))

def print_detections(detections):
    infected_count = 0
    for av_name, av_results in detections.items():
        if 'infected' not in av_results or 'error' in av_results and av_results['error']:
            continue
        if av_results['infected'] and 'result' in av_results:
            infected_count += 1
    print_header('AV Engine Detections ({}/{})'.format(infected_count, len(detections)))
    for av_name, av_results in detections.items():
        if 'infected' not in av_results or 'error' in av_results and av_results['error']:
            continue
        if av_results['infected'] and 'result' in av_results:
            print('{}: {}'.format(av_name, av_results['result']))
        else:
            print('{}: Undetected'.format(av_name))

def print_pull_dockers(pull_results):
    print_header('Pull docker images')
    for image_name, image_result in pull_results.items():
        print('\n-- {} --'.format(image_name))
        print('{}'.format('\n'.join(map(str, image_result))))

def print_update(update_results):
    print_header('Update antivirus databases')
    for image_name, update_result in update_results.items():
        print('\n-- {} --'.format(image_name))
        print('{}'.format('\n'.join(map(str, update_result))))

def print_av_list(av_list):
    print_header('List of available antivirus engines')
    print('{}'.format('\n'.join(map(str, av_list))))

def exit(with_help=False):
    if with_help:
        parser.print_help()
    loop.close()
    sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', dest='debug', help="Enable debug mode")
    parser.add_argument('-j', '--json', action='store_true', dest='json', help="Retrive response in JSON format")
    exclusive = parser.add_mutually_exclusive_group()
    exclusive.add_argument('-s', '--scan-file', const='scan_file', type=str, dest='file', nargs='?', help='Scan a specific file')
    exclusive.add_argument('-p', '--pull-dockers', action='store_const', const='pull_dockers', help='Pull all the images from the configuration file')
    exclusive.add_argument('-l', '--list-avs', action='store_const', const='list_avs', help='List of available antivirus engines')
    exclusive.add_argument('-u', '--update-avs', action='store_const', const='update_avs', help='Update antivirus databases')
    exclusive.add_argument('-i', '--file-info', const='file_info', type=str, dest='fileinfo', nargs='?', help='Retrieve file information (File info, Portable Executable Info, Imported DLLs)')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.ERROR, format='%(levelname)s: %(message)s')

    if not is_docker_installed():
        logging.error("Docker needs to be installed")
        exit()

    if not is_docker_configuration_available(DOCKER_CONFIG_PATH):
        logging.error("Configuration is not valid or is not accessible. Please, check that file {} exists".format(DOCKER_CONFIG_PATH))
        exit()

    try:
        if args.file:
            if not is_a_valid_file(args.file):
                logging.error("File is missing or not readable")
                exit(True)
            my_function, my_args = scan_file, (args.file, args.json,)
        elif args.pull_dockers:
            my_function, my_args = pull_dockers, (args.json,)
        elif args.list_avs:
            my_function, my_args = list_available_antivirus, (args.json,)
        elif args.update_avs:
            my_function, my_args = update_antivirus, (args.json,)
        elif args.fileinfo:
            if not is_a_valid_file(args.fileinfo):
                logging.error("File is missing or not readable")
                exit(True)
            my_function, my_args = print_file_info, (args.fileinfo, args.json,)
        else:
            exit(True)

        my_function(*my_args)

    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.error(e)
        if args.debug:
            raise
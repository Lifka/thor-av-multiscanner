# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera. <javierizquierdovera.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import argparse
import sys
import os
import asyncio
from core import scanner
from core.utils import is_docker_installed, is_a_valid_file

loop = asyncio.get_event_loop()

def scan_file(file):
    results = loop.run_until_complete(scanner.scan_file_async(file, loop))
    print(results)

def list_avs():
    print('TODO')


def exit(with_help=False):
    if with_help:
        parser.print_help()
    loop.close()
    sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', dest='debug', help="Enable debug mode")
    exclusive = parser.add_mutually_exclusive_group()
    exclusive.add_argument('-s', '--scan-file', const='scan_file', type=str, dest='file', nargs='?', help='Scan a specific file')
    exclusive.add_argument('-l', '--list-avs', action='store_const', const='list_avs', help='List of available antivirus engines')
    exclusive.add_argument('-u', '--update-avs', action='store_const', const='update_avs', help='Update antivirus databases')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.ERROR, format='%(levelname)s: %(message)s')

    if not is_docker_installed():
        logging.error("Docker needs to be installed")
        exit()

    try:
        if args.file:
            if not is_a_valid_file(args.file):
                logging.error("File is missing or not readable")
                exit(True)
            my_function, my_args = scan_file, (args.file,)
        elif args.list_avs:
            my_function, my_args = list_avs, ()
        elif args.update_avs:
            print("TODO")
        else:
            exit(True)

        my_function(*my_args)

    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.error(e)
        if args.debug:
            raise
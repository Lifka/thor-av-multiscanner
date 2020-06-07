# /usr/bin/python3

# Copyright (C) 2020
# Created by Javier Izquierdo Vera. <javierizquierdovera.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging
import argparse
import sys
import os
import re
import subprocess

docker_version = subprocess.check_output('docker -v', shell=True).decode('utf-8')

def check_for_docker():
    if not re.compile(r'version').search(docker_version):
        logging.error("Docker needs to be installed")
        sys.exit(0)

   
async def scan_file(file):
    print("asdf")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', dest='debug', help="Enable debug mode")
    exclusive = parser.add_mutually_exclusive_group()
    exclusive.add_argument('-s', '--scan-file', const='scan_file', type=str, dest='file', nargs='?', help='Scan a specific file')
    exclusive.add_argument('-l', '--list-avs', action='store_const', const='list_avs', help='List of available antivirus engines')
    exclusive.add_argument('-u', '--update-avs', action='store_const', const='update_avs', help='Update antivirus databases')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.ERROR, format='%(levelname)s: %(message)s')

    check_for_docker()

    try:
        if args.file:
            my_function, my_args = scan_file, (args.file,)
        elif args.list_avs:
            print("TODO")
        elif args.update_avs:
            print("TODO")
        else:
            parser.print_help()
            sys.exit(0)

        asyncio.run(my_function(*my_args))

    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.error(e)
        if args.debug:
            raise
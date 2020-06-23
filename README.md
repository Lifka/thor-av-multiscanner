# Thor AV Multiscanner
Scan files locally with various antivirus using Docker.

## CLI
The CLI allows you to use the scanner without having to deploy the web application.

```
usage: thor.py [-h] [-d] [-s [FILE] | -l | -u]

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           Enable debug mode
  -s [FILE], --scan-file [FILE]
                        Scan a specific file
  -l, --list-avs        List of available antivirus engines
  -u, --update-avs      Update antivirus databases
```

## Web APP

## Configuration
This application uses a file in JSON format where the Docker commands that will be used for operations with each of the antivirus are indicated. Each object in the list represents an antivirus configured in a Docker container.

```
{
    "name":"AVG AntiVirus",
    "scan_command": "--rm -v \"{File_path}:/malware/{File_name}\" malice/avg {File_name}",
    "update_command": "malice/avg update"
}
```

The commands are parameterized, being necessary to indicate the path of the file to be used and the name of the file.
* File_path: This token will be replaced by the path of the file to analyze.
* File_name: This token will be replaced by the name of the file to analyze.


## AntiVirus

## About

## Copyright
© 2020 Copyright: [javierizquierdovera.com](https://javierizquierdovera.com/).
This program is free software, you can redistribute it and/or modify it under the terms of [GPLv2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html).
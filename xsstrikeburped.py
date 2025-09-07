#!/usr/bin/env python3

import sys
import json
import os
import argparse
import warnings
import base64
import xml.etree.ElementTree as ET

import core.config
import core.log
from core.config import blind_xss_payload
from core.utils import reader
from core.scan import scan
from core.colors import end, red, white, bad, info, blue
from core.burper import BurpRequest, identify_burp_request_type_and_params, request_dupe_check


warnings.filterwarnings("ignore")

logger = core.log.setup_logger()

def banner() -> None:
    print('''\n  
            \033[1m\033[34m     __   __  ___  __          ___\033[0m\033[0m   __        __   __   ___  __  
            \033[1m\033[34m\_/ /__` /__`  |  |__) | |__/ |__ \033[0m\033[0m  |__) |  | |__) |__) |__  |  \ 
            \033[1m\033[34m/ \ .__/ .__/  |  |  \ | |  \ |___\033[0m\033[0m  |__) \__/ |  \ |    |___ |__/ 
            version 1.0.0beta
        ''')


def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', help='burp export file', dest='burp_file')
    parser.add_argument('--header' ,help='provide an additional header or replace an existing one', dest='header', action='append')
    parser.add_argument('--delay', help='delay between requests', dest='delay', type=int, default=core.config.delay)
    parser.add_argument('--timeout', help='timeout',dest='timeout', type=int, default=core.config.timeout)
    parser.add_argument('--skip', help='don\'t ask to continue', dest='skip', action='store_true')
    parser.add_argument('--blind', help='inject blind XSS payload', dest='blind_xss')
    parser.add_argument('--path', help='inject payloads in the path', dest='path', action='store_true')
    parser.add_argument('--proxy', help='use prox(y|ies)',dest='proxy', action='store_true')
    args = parser.parse_args()
    return args

def main() -> None:
    args = get_args()

    core.config.globalVariables = vars(args)
    core.config.globalVariables['checkedScripts'] = set()
    core.config.globalVariables['checkedForms'] = {}
    core.config.globalVariables['definitions'] = json.loads('\n'.join(reader(sys.path[0] + '/db/definitions.json')))
    
    burp_file = args.burp_file
    timeout = args.timeout
    delay = args.delay
    skip = args.skip
    proxy = args.proxy
    blind_xss = args.blind_xss
    path = args.path
    
    custom_headers = {}
    if args.header:
        for header in args.header:
            custom_headers[header.split(':')[0].strip()] = ''.join(header.split(':')[1:])

    if blind_xss:
        core.config.blind_xss_payload = blind_xss
        
    if path:
        core.config.inject_path = True

    if not proxy:
        core.config.proxies = {}

    if not burp_file:
        logger.no_format('\nProvide a burp file.')
        quit()
    
    if not os.path.isfile(burp_file):
        logger.no_format('\nProvided burp file does not exist.')
        quit()

    tree = ET.parse(burp_file)
    root = tree.getroot()
    
    try:

        burp_requests = []

        for item in root.findall('item'):
            
            request = item.find('request').text
            is_base64_encoded = item.find('request').attrib['base64']
            
            request_arr = []
            
            if is_base64_encoded.lower() == 'true':
                try:
                    request_arr = base64.b64decode(str(request)).decode().splitlines()
                except Exception as e:
                    continue
            else:
                request_arr = request.splitlines()
            
            method = request_arr[0].split(" ")[0]
            url = item.find('url').text
            headers = {}
            body = None
            
            for header in request_arr[2:]:
                if len(header.replace(" ", "")) > 0 and len(header.split(":")) == 1 or header.lstrip().startswith("{"):
                    body = header
                    body_json = True
                    break
                if len(header.replace(" ", "")) > 0:
                    headers[header.split(":")[0].strip()] = ''.join(header.split(":")[1:]).strip()
            
            # Add custom headers or replace existing ones with custom headers
            for header in custom_headers:
                headers[header] = custom_headers[header]
                                    
            request_type, params = identify_burp_request_type_and_params(method, url, body)
            burp_req = BurpRequest(method=method, url=url, headers=headers, params=params, request_type=request_type)
            if not request_dupe_check(burp_requests, burp_req):
                burp_requests.append(burp_req)

        counter = 0
        total = len(burp_requests)
        
        for burp_req in burp_requests:
            counter += 1
            if burp_req.method == "GET" or burp_req.method == "POST": # only process GET and POST requests
                logger.white_line()
                logger.info('\033[1m[{}/{}] Scan Target: {} ({})\033[0m'.format(counter, total, burp_req.url, burp_req.method))
                scan(burp_req, delay, timeout, skip)

    except Exception as e:
        logger.error(e)
        sys.exit(1)


if __name__ == "__main__":
    banner()
    main()
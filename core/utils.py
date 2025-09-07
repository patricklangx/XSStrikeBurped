import json
import random
import re
import os
from urllib.parse import urlparse, parse_qs, parse_qsl
import base64 as b64

import core.config
from core.config import xsschecker
from core.log import setup_logger

from core.burper import BurpRequest

logger = setup_logger(__name__)


def counter(string: str)->int:
    string = re.sub(r'\s|\w', '', string)
    return len(string)


def closest(number, numbers):
    difference = [abs(list(numbers.values())[0]), {}]
    for index, i in numbers.items():
        diff = abs(number - i)
        if diff < difference[0]:
            difference = [diff, {index: i}]
    return difference[1]


def fillHoles(original, new):
    filler = 0
    filled = []
    for x, y in zip(original, new):
        if int(x) == (y + filler):
            filled.append(y)
        else:
            filled.extend([0, y])
            filler += (int(x) - y)
    return filled


def stripper(string, substring, direction='right'):
    done = False
    strippedString = ''
    if direction == 'right':
        string = string[::-1]
    for char in string:
        if char == substring and not done:
            done = True
        else:
            strippedString += char
    if direction == 'right':
        strippedString = strippedString[::-1]
    return strippedString


def extractHeaders(headers):
    headers = headers.replace('\\n', '\n')
    sorted_headers = {}
    matches = re.findall(r'(.*):\s(.*)', headers)
    for match in matches:
        header = match[0]
        value = match[1]
        try:
            if value[-1] == ',':
                value = value[:-1]
            sorted_headers[header] = value
        except IndexError:
            pass
    return sorted_headers


def replaceValue(mapping, old, new, strategy=None):
    """
    Replace old values with new ones following dict strategy.

    The parameter strategy is None per default for inplace operation.
    A copy operation is injected via strateg values like copy.copy
    or copy.deepcopy

    Note: A dict is returned regardless of modifications.
    """
    anotherMap = strategy(mapping) if strategy else mapping
    if old in anotherMap.values():
        for k in anotherMap.keys():
            if anotherMap[k] == old:
                anotherMap[k] = new
    return anotherMap


def extractScripts(response):
    scripts = []
    matches = re.findall(r'(?s)<script.*?>(.*?)</script>', response.lower())
    for match in matches:
        if xsschecker in match:
            scripts.append(match)
    return scripts


def randomUpper(string):
    return ''.join(random.choice((x, y)) for x, y in zip(string.upper(), string.lower()))


def flattenParams(currentParam, params, payload):
    flatted = []
    for name, value in params.items():
        if name == currentParam:
            value = payload
        flatted.append(name + '=' + value)
    return '?' + '&'.join(flatted)


def genGen(fillings, eFillings, lFillings, eventHandlers, tags, functions, ends, badTag=None):
    vectors = []
    r = randomUpper  # randomUpper randomly converts chars of a string to uppercase
    for tag in tags:
        if tag == 'd3v' or tag == 'a':
            bait = xsschecker
        else:
            bait = ''
        for eventHandler in eventHandlers:
            # if the tag is compatible with the event handler
            if tag in eventHandlers[eventHandler]:
                for function in functions:
                    for filling in fillings:
                        for eFilling in eFillings:
                            for lFilling in lFillings:
                                for end in ends:
                                    if tag == 'd3v' or tag == 'a':
                                        if '>' in ends:
                                            end = '>'  # we can't use // as > with "a" or "d3v" tag
                                    breaker = ''
                                    if badTag:
                                        breaker = '</' + r(badTag) + '>'
                                    vector = breaker + '<' + r(tag) + filling + r(
                                        eventHandler) + eFilling + '=' + eFilling + function + lFilling + end + bait
                                    vectors.append(vector)
    return vectors




def is_base64_encoded(string: str) -> bool:
    try:
        string.encode('ascii')
    except UnicodeEncodeError:
        return False

    pattern = r'^[A-Za-z0-9+/=]+$'
    if re.match(pattern, string) and len(string) % 4 == 0:
        return True
    else:
        return False


def writer(obj, path):
    kind = str(type(obj)).split('\'')[0]
    if kind == 'list' or kind == 'tuple':
        obj = '\n'.join(obj)
    elif kind == 'dict':
        obj = json.dumps(obj, indent=4)
    savefile = open(path, 'w+')
    savefile.write(str(obj.encode('utf-8')))
    savefile.close()


def reader(path):
    with open(path, 'r') as f:
        result = [line.rstrip(
                    '\n').encode('utf-8').decode('utf-8') for line in f]
    return result

def js_extractor(response):
    """Extract js files from the response body"""
    scripts = []
    matches = re.findall(r'<(?:script|SCRIPT).*?(?:src|SRC)=([^\s>]+)', response)
    for match in matches:
        match = match.replace('\'', '').replace('"', '').replace('`', '')
        scripts.append(match)
    return scripts


def handle_anchor(parent_url, url):
    scheme = urlparse(parent_url).scheme
    if url[:4] == 'http':
        return url
    elif url[:2] == '//':
        return scheme + ':' + url
    elif url.startswith('/'):
        host = urlparse(parent_url).netloc
        scheme = urlparse(parent_url).scheme
        parent_url = scheme + '://' + host
        return parent_url + url
    elif parent_url.endswith('/'):
        return parent_url + url
    else:
        return parent_url + '/' + url


def deJSON(data):
    return data.replace('\\\\', '\\')


def getVar(name: str)->str:
    return core.config.globalVariables[name]

def updateVar(name, data, mode=None):
    if mode:
        if mode == 'append':
            core.config.globalVariables[name].append(data)
        elif mode == 'add':
            core.config.globalVariables[name].add(data)
    else:
        core.config.globalVariables[name] = data

def isBadContext(position, non_executable_contexts):
    badContext = ''
    for each in non_executable_contexts:
        if each[0] < position < each[1]:
            badContext = each[2]
            break
    return badContext

def equalize(array, number):
    if len(array) < number:
        array.append('')

def escaped(position, string):
    usable = string[:position][::-1]
    match = re.search(r'^\\*', usable)
    if match:
        match = match.group()
        if len(match) == 1:
            return True
        elif len(match) % 2 == 0:
            return False
        else:
            return True
    else:
        return False
    
    
def base64_encode(string: str)->str:
    if re.match(r'^[A-Za-z0-9+\/=]+$', string) and (len(string) % 4) == 0:
        return b64.b64decode(string.encode('utf-8')).decode('utf-8')
    else:
        return b64.b64encode(string.encode('utf-8')).decode('utf-8')


def output_json(burp_request:BurpRequest, param: str, payload: str, bestEfficiency: int):

    file_name = core.config.output_file

    new_obj = {"url": burp_request.url, "method": burp_request.method, "headers": burp_request.headers, "params_body": burp_request.params, "vulnerable_param": param, "payload": payload, "bestEfficiency": bestEfficiency}

    if not os.path.exists(file_name):
        with open(file_name, 'w', encoding='utf-8') as f:
            json.dump([], f)

    with open(file_name, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    if not isinstance(data, list):
        raise ValueError('Expected top-level JSON array')
    
    data.append(new_obj)

    with open(file_name, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


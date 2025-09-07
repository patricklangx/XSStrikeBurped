#!/usr/bin/env python3

from enum import Enum
from urllib.parse import urlparse
from typing import Tuple
import json

class BurpRequest:
    def __init__(self, method: str, url: str, headers: dict[str, str], params: dict[str, str], request_type: int):
        self.method = method
        self.url = url
        self.headers = headers
        self.params = params
        self.request_type = request_type
        
        
class BurpRequestType(Enum):
    GET_URL = 1 # GET with params in url, body is empty
    POST_URL = 2 # POST with params in url, body is empty
    POST_PARAM = 3 # POST with params (e.g. key1=value1&key2=value2) in body
    POST_JSON = 4 # POST with json in body
    OTHER = 5 # Other request types like PUT, DELETE, etc. or multipart/form-data or malformed requests
    
    
def identify_burp_request_type_and_params(method: str, url: str, body: str) -> Tuple[int, dict]:
    params = {}
    
    if method.upper() == 'GET' and '?' in url and '=' in url:
        params = extract_query_params(urlparse(url).query)
        return BurpRequestType.GET_URL.value, params
    
    elif method.upper() == 'POST':
        if ('?' in url) and ('=' in url) and (body is None or body.replace(' ', '') == ''):
            params = extract_query_params(urlparse(url).query)
            return BurpRequestType.POST_URL.value, params
        
        elif is_json(body):
            params = json.loads(body)
            return BurpRequestType.POST_JSON.value, params
        
        elif (body is not None) and ('=' in body) and (len(extract_query_params(body)) > 0):
            params = extract_query_params(body)
            if ('?' in url) and ('=' in url):
                params.update(extract_query_params(urlparse(url).query))
            return BurpRequestType.POST_PARAM.value, params
        
        else:
            return BurpRequestType.OTHER.value, params
    else:
        return BurpRequestType.OTHER.value, params

def request_dupe_check(burp_requests: list[BurpRequest], request: BurpRequest) -> bool:
    for req in burp_requests:
        if req.method == request.method and req.url == request.url and req.params == request.params and req.request_type == request.request_type:
            return True
    return False

def extract_query_params(query: str) -> dict:
    params = {}
    try:
        for v in query.split("&"):
            params[v.split("=")[0]] = v.split("=")[1]
    except: pass
    return params

def is_json(data: str) -> bool:
    try: json.loads(data); return True
    except: return False
    
def __str__(self) -> str:
        return f"BurpRequest(method={self.method}, url={self.url}, headers={self.headers}, params={self.params}, request_type={self.request_type})"
    
    
import json
import re
import sys

from core.requester import requester
from core.log import setup_logger

logger = setup_logger(__name__)


def wafDetector(url: str, params: dict, headers: dict, GET: bool, request_type: int, delay: int, timeout: int):
    
    logger.debug_json('Waf Detector params:', params)
    
    with open(sys.path[0] + '/db/wafSignatures.json', 'r') as file:
        wafSignatures = json.load(file)
        
    # a payload which is noisy enough to provoke the WAF
    noise = '<script>alert("XSS")</script>'
    params['xss'] = noise
    
    logger.debug_json('Payloaded Waf Detector params:', params)
    
    # Opens the noise injected payload
    response = requester(url, params, headers, GET, request_type, delay, timeout)
    
    page = response.text
    code = str(response.status_code)
    headers = str(response.headers)
    
    logger.info('Waf Detector code: {}'.format(code))
    logger.debug_json('Waf Detector headers:', response.headers)
    #logger.debug('Waf Detector page: {}'.format(page))
        
    if code == 'None':
        return None
    
    if int(code) >= 400:
        logger.debug('Waf Detector: Analyzing response')
        bestMatch = [0, None]
        for wafName, wafSignature in wafSignatures.items():
            score = 0
            pageSign = wafSignature['page']
            codeSign = wafSignature['code']
            headersSign = wafSignature['headers']
            if pageSign:
                if re.search(pageSign, page, re.I):
                    score += 1
            if codeSign:
                if re.search(codeSign, code, re.I):
                    score += 0.5  # increase the overall score by a smaller amount because http codes aren't strong indicators
            if headersSign:
                if re.search(headersSign, headers, re.I):
                    score += 1
            # if the overall score of the waf is higher than the previous one
            if score > bestMatch[0]:
                del bestMatch[:]  # delete the previous one
                bestMatch.extend([score, wafName])  # and add this one
        if bestMatch[0] != 0:
            return bestMatch[1]
        else:
            return None
    else:
        return None

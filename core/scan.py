import copy
from urllib.parse import urlparse, unquote

from core.checker import checker
from core.colors import end, green, que, blue, red
import core.config
from core.config import xsschecker, minEfficiency
from core.filterChecker import filterChecker
from core.generator import generator
from core.htmlParser import htmlParser
from core.requester import requester
from core.wafDetector import wafDetector
from core.log import setup_logger
from core.utils import output_json

from core.burper import BurpRequest

logger = setup_logger(__name__)

def scan(burp_request:BurpRequest, delay:int, timeout:int, skip:bool) -> None:
    
    method = burp_request.method
    url = burp_request.url
    params = burp_request.params
    headers = burp_request.headers
    encoding = None
    delay = delay
    timeout = timeout
    skip = skip
    request_type = burp_request.request_type
    
    GET = None
    POST = None
    
    if method == 'GET':
        GET, POST = (True, False)
    else:
        GET, POST = (False, True)
    
    host = urlparse(url).netloc
    logger.debug('Host to scan: {}'.format(host))
    
    response = requester(url, params, headers, GET, request_type, delay, timeout).text
    
    
    logger.debug_json('Scan parameters:', params)
    if not params:
        logger.error('No parameters to test.')
    
    else:
        WAF = wafDetector(url, {list(params.keys())[0]: xsschecker}, headers, GET, request_type, delay, timeout)
        if WAF:
            logger.error('WAF detected: %s%s%s' % (green, WAF, end))
        else:
            logger.good('WAF Status: %sOffline%s\n' % (green, end))

        for paramName in params.keys():
            paramsCopy = copy.deepcopy(params)
            logger.info('Testing parameter: %s' % paramName)
            paramsCopy[paramName] = xsschecker
            
            logger.debug_json('Request with parameters:', paramsCopy)
            response = requester(url, paramsCopy, headers, GET, request_type, delay, timeout)

            # send blind xss payload if set
            if core.config.blind_xss_payload is not None:
                paramsBlindCopy = copy.deepcopy(params)
                paramsBlindCopy[paramName] = core.config.blind_xss_payload
                logger.info('Send blind XSS payload to parameter: %s' % paramName)
                requester(url, paramsBlindCopy, headers, GET, request_type, delay, timeout)
            
            occurences = htmlParser(response, encoding)
            positions = occurences.keys()
            logger.debug('Scan occurences: {}'.format(occurences))
            if not occurences:
                logger.error('No reflection found')
                continue
            else:
                logger.info('Reflections found: %i' % len(occurences))

            logger.run('Analysing reflections')

            efficiencies = filterChecker(url, paramsCopy, headers, GET, request_type, delay, occurences, timeout, encoding)
            
            logger.debug('Scan efficiencies: {}'.format(efficiencies))
            
            logger.run('Generating payloads')
            vectors = generator(occurences, response.text)
            total = 0
            for v in vectors.values():
                total += len(v)
            if total == 0:
                logger.error('No vectors were crafted.')
                continue
            logger.info('Payloads generated: %i' % total)
            progress = 0
            for confidence, vects in vectors.items():
                for vect in vects:
                    if core.config.inject_path:
                        vect = vect.replace('/', '%2F')
                    loggerVector = vect
                    progress += 1
                    logger.run('Progress: %i/%i\r' % (progress, total))
                    if not GET:
                        vect = unquote(vect)
                    efficiencies = checker(url, paramsCopy, headers, GET, request_type, delay, vect, positions, timeout, encoding)
                    if not efficiencies:
                        for i in range(len(occurences)):
                            efficiencies.append(0)
                    bestEfficiency = max(efficiencies)
                    logger.debug('Efficiency: %i' % (bestEfficiency))
                    if bestEfficiency >= 93:
                        logger.good('Efficiency: {}{}{} | Payload: {}{}{}'.format(green, bestEfficiency, end, green, loggerVector, end))
                        output_json(burp_request, paramName, loggerVector, bestEfficiency)
                        if not skip:
                            choice = input(
                                '%s Would you like to continue scanning? [y/N] ' % que).lower()
                            if choice != 'y':
                                break
                    elif bestEfficiency >= minEfficiency:
                        logger.good('Efficiency: {}{}{} | Payload: {}{}{}'.format(green, bestEfficiency, end, green, loggerVector, end))
                        output_json(burp_request, paramName, loggerVector, bestEfficiency)
            logger.no_format('')

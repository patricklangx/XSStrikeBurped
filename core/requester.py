import requests
import time
from urllib3.exceptions import ProtocolError
import warnings
from urllib.parse import urlparse, parse_qsl
import json
from core.burper import BurpRequestType

import core.config
from core.log import setup_logger

logger = setup_logger(__name__)

warnings.filterwarnings('ignore')  # Disable SSL related warnings


def requester(url: str, params: dict, headers: dict, GET: bool, request_type: int, delay: int, timeout: int)-> requests.Response:
        
    time.sleep(delay)

    logger.debug('Requester url: {}'.format(url))
    logger.debug('Requester GET: {}'.format(GET))
    logger.debug_json('Requester params:', params)
    logger.debug_json('Requester headers:', headers)
    
    try:
        if request_type == BurpRequestType.GET_URL.value:
            logger.debug('GET request case 1')
        
            url = url.split('?')[0]
            
            logger.debug('GET Requester url: {}'.format(url))
            logger.debug_json('GET Requester params:', params)
            
            response = requests.get(url, params=params, headers=headers, timeout=timeout, verify=False, proxies=core.config.proxies)
            
            #logger.debug_json('Requester response:', response.text)
            
        elif request_type == BurpRequestType.POST_URL.value:
            logger.debug('POST request case 2')
            
            url = url.split('?')[0]
            
            logger.debug('POST Requester url: {}'.format(url))
            logger.debug_json('POST Requester params:', params)
            
            response = requests.post(url, params=params, data={}, headers=headers, timeout=timeout, verify=False, proxies=core.config.proxies)
            
            #logger.debug_json('Requester response:', response.text)
            
        elif request_type == BurpRequestType.POST_PARAM.value:
            logger.debug('POST request case 3')
            
            data = params

            logger.debug('POST Requester url: {}'.format(url))
            logger.debug_json('POST Requester body:', data)
            
            response = requests.post(url, data=data, headers=headers, timeout=timeout, verify=False, proxies=core.config.proxies)
            
            #logger.debug_json('Requester response:', response.text)
        
        elif request_type == BurpRequestType.POST_JSON.value:
            logger.debug('POST request case 4')
            
            json_data = json.dumps(params)
            
            logger.debug('POST Requester url: {}'.format(url))
            logger.debug_json('POST Requester body:', json_data)
            
            response = requests.post(url, json=json_data, headers=headers, timeout=timeout, verify=False, proxies=core.config.proxies)
            
            #logger.debug_json('Requester response:', response.text)
            
        else:
            logger.warning('None of the request types matched.')
            return requests.Response()
            
        return response
    
    except ProtocolError:
        logger.warning('WAF is dropping suspicious requests.')
        logger.warning('Scanning will continue after 10 minutes.')
        time.sleep(600)
    except Exception as e:
        logger.warning('Unable to connect to the target: {}'.format(e))
        #traceback.print_exc()
        return requests.Response()




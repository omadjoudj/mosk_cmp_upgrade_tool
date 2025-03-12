#!/usr/bin/python
# A small module to interact with Nemo ChangeMan written from scratch to avoid external dependencies
# Customization owner: omadjoudj

from http.client import HTTPSConnection
from base64 import b64encode
import configparser
import json
import logging
import os

LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()

formatter = logging.Formatter(
    fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger('nemo_client')
logger.setLevel(LOGLEVEL)
logger.addHandler(handler)


def rest_client(verb, url, username, password, body=None, headers=None):
    hostname = url.replace("https://", "").split('/')[0]
    path = '/' + '/'.join(url.split('/')[3:])
    
    token = b64encode(f"{username}:{password}".encode('utf-8')).decode("ascii")
    base_headers = {'Authorization': f'Basic {token}'}
    
    final_headers = base_headers.copy()
    if headers:
        final_headers.update(headers)
    
    if body is not None:
        if isinstance(body, dict):
            body = json.dumps(body)
            print(body)
            final_headers['Content-Type'] = 'application/json'
        elif isinstance(body, str):
            final_headers['Content-Type'] = 'application/json'
        else:
            raise ValueError("Body must be dict or string")
    
    conn = HTTPSConnection(hostname)
    conn.request(verb, path, body=body, headers=final_headers)
    response = conn.getresponse()
    return response

def get_cr(cr_id, nemo_api_endpoint, nemo_api_service_user, nemo_api_service_user_password):
    return rest_client('GET', f'{nemo_api_endpoint}/change_man/api/v1/cr/{cr_id}/', nemo_api_service_user, nemo_api_service_user_password)

def fetch_crs_list(nemo_api_endpoint, nemo_api_service_user, nemo_api_service_user_password, limit=1000000, on_date="", status="planned"):
    return rest_client('GET', f'{nemo_api_endpoint}/change_man/api/v1/cr/?limit={limit}&on_date={on_date}&status={status}', nemo_api_service_user, nemo_api_service_user_password)


def create_cr(summary, planned_start_date, planned_end_date, hosts, nemo_api_endpoint, nemo_api_service_user, nemo_api_service_user_password, dryrun=False):
    status="planned"
    cr_template_json=f"""
    {{
        "summary": "{summary}",
        "planned_start_date":"{planned_start_date}",
        "planned_end_date":"{planned_end_date}",
        "type": "normal_change",
        "status": "{status}",
        "subtype": "PrivateCloud_normal_change",
        "hosts": {hosts}
    }}
    """
    if dryrun == True:
        logger.debug(f"POST: \n {cr_template_json}")
        return
    else:
        logger.debug(f"POST: \n {cr_template_json}")
        r = rest_client('POST', f'{nemo_api_endpoint}/change_man/api/v1/cr/', nemo_api_service_user, nemo_api_service_user_password,cr_template_json)
        logger.debug(f"Nemo create API call return: Status: {r.status}, Reason: {r.reason}")
        if r.status != 201:
            logger.error(f"Nemo call returned {r.status}")
        return r
        

def parse_config():
    config = configparser.ConfigParser()
    config.read('cmp_upgrade_tool.conf')
    #nemo_api_endpoint=config["nemo"]["nemo_api_endpoint"]
    #nemo_api_service_user=config["nemo"]["nemo_api_service_user"]
    #nemo_api_service_user_password=config["nemo"]["nemo_api_service_user_password"]
    return config['nemo']



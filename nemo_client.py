#!/usr/bin/python

from http.client import HTTPSConnection
from base64 import b64encode
import configparser
import json

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


def create_cr(nemo_api_endpoint, nemo_api_service_user, nemo_api_service_user_password, summary, planed_start_date, planned_end_date, hosts, status='draft'):
    cr_template_json=""" 
    {
        "summary": "[opscare][ams-pc5][z04r06b15] kaas-node-1807849f-6e48-49d7-a878-51bdb8139c06 maintenance 2",
        "planned_start_date":"2025-05-01T16:00",
        "planned_end_date":"2025-05-01T18:00",
        "type": "normal_change",
        "subtype": "PrivateCloud_normal_change",
        "hosts": [
            {
            "vm_id": "a75add04-4f5f-49a5-9340-c408b19e0ca4",
            "fqdn": "dwdb-1006.42w4rm.pc5.ams4.prod.booking.com",
            "sd_project": "mysql-replication-chains",
            "sd_component": "dwdb",
            "rack": "z04r06b15",
            "hypervisor": "kaas-node-1807849f-6e48-49d7-a878-51bdb8139c06"
            },
            {
            "vm_id": "9dd67664-39ad-4b23-9213-3c7d53182af1",
            "fqdn": "balancerdb-1008.o2fud3.pc5.ams4.prod.booking.com",
            "sd_project": "mysql-replication-chains",
            "sd_component": "balancerdb",
            "rack": "z04r06b15",
            "hypervisor": "kaas-node-1807849f-6e48-49d7-a878-51bdb8139c06"
            }

        ]
    }
    """
    return rest_client('POST', f'{nemo_api_endpoint}/change_man/api/v1/cr/', nemo_api_service_user, nemo_api_service_user_password,cr_template_json)

if __name__ == "__main__":

    # Example usage
    config = configparser.ConfigParser()
    config.read('cmp_upgrade_tool.conf')
    nemo_api_endpoint=config["DEFAULT"]["nemo_api_endpoint"]
    nemo_api_service_user=config["DEFAULT"]["nemo_api_service_user"]
    nemo_api_service_user_password=config["DEFAULT"]["nemo_api_service_user_password"]
    #r = get_cr(1961, nemo_api_endpoint, nemo_api_service_user, nemo_api_service_user_password)
    #r = create_cr(nemo_api_endpoint, nemo_api_service_user, nemo_api_service_user_password, "Test")
    print(json.loads(r.read()))

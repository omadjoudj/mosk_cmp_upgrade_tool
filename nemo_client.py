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
            final_headers['Content-Type'] = 'application/json'
        elif isinstance(body, str):
            final_headers['Content-Type'] = 'text/plain'
        else:
            raise ValueError("Body must be dict or string")
    
    # Make request
    conn = HTTPSConnection(hostname)
    conn.request(verb, path, body=body, headers=final_headers)
    response = conn.getresponse()
    return response

if __name__ == "__main__":
    cr_status='draft'
    cr_template = {
        'id': 0, 
        'planned_start_date': '2025-05-01T16:00:00', 
        'planned_end_date': '2025-05-01T18:00:00', 
        'actual_start_date': '2025-05-01T16:00:00', 
        'actual_end_date': '2025-05-01T16:00:00', 
        'template': {
            'name': 'PrivateCloud_normal_change', 'cr_type': 'normal_change', 'team': 'PrivateCloud', 'potential_impact': None, 'complexity': None, 'summary': None, 'description': None, 'change_plan': None, 'rollback_plan': None, 'require_approval': False, 'require_review': False, 'auto_create_ticket': False, 'auto_create_calendar_event': False, 'executor_name': None, 'executable': None, 'params': [], 'custom_params': None, 'auto_start': True, 'timeout': 60, 'log_streaming': False, 'console_streaming': False, 'ping_streaming': False
            },
        'email': 'bcom-opscare-team@mirantis.com', 
        'hosts': [
             {'vm_id': 'a75add04-4f5f-49a5-9340-c408b19e0ca4', 'fqdn': 'dwdb-1006.42w4rm.pc5.ams4.prod.booking.com', 'sd_project': 'mysql-replication-chains', 'sd_component': 'dwdb', 'rack': 'z04r06b15', 'hypervisor': 'kaas-node-1807849f-6e48-49d7-a878-51bdb8139c06'}, {'vm_id': '9dd67664-39ad-4b23-9213-3c7d53182af1', 'fqdn': 'balancerdb-1008.o2fud3.pc5.ams4.prod.booking.com', 'sd_project': 'mysql-replication-chains', 'sd_component': 'balancerdb', 'rack': 'z04r06b15', 'hypervisor': 'kaas-node-1807849f-6e48-49d7-a878-51bdb8139c06'}
             ],
        'type': 'normal_change', 
        'subtype': 'PrivateCloud_normal_change', 
        'status': cr_status, 
        'potential_impact': None, 
        'complexity': None, 
        'ticket': None, 
        'summary': '[opscare][ams-pc5][z04r06b15] kaas-node-1807849f-6e48-49d7-a878-51bdb8139c06 maintenance', 
        'description': None, 
        'change_plan': None, 
        'rollback_plan': None, 
        'acceptance_criteria': None, 
        'test_evidence': None, 
        'actual_impact': False, 
        'metadata': {}, 
        'calendar_id': None, 
        'parent_ticket': None, 
        'rfo': None, 
        'auto_downtime': False, 
        'downtime_status': None, 
        'owner': None, 
        'backup_owner': None, 
        'review': None, 
        'approve': None, 
        'second_review': None, 
        'communication_channels': [], 
        'regions': [], 
        'products': [], 
        'devices': []
    }
    # Example usage
    config = configparser.ConfigParser()
    config.read('cmp_upgrade_tool.conf')
    nemo_api_endpoint=config["DEFAULT"]["nemo_api_endpoint"]
    nemo_api_service_user=config["DEFAULT"]["nemo_api_service_user"]
    nemo_api_service_user_password=config["DEFAULT"]["nemo_api_service_user_password"]
    #r = rest_client('GET', f'{nemo_api_endpoint}/change_man/api/v1/cr/1961/', nemo_api_service_user, nemo_api_service_user_password)
    r = rest_client('POST', f'{nemo_api_endpoint}/change_man/api/v1/cr/', nemo_api_service_user, nemo_api_service_user_password,cr_template)
    print(json.loads(r.read()))

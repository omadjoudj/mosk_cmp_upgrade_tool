#!/usr/bin/python3
# Customization owner: omadjoudj

## NOTE:

# openstack client and kubectl are used directly instead of corresponding Python libraries to reduce the dependencies on external libraries

# This script is used by trusted users, data validation was skipped

#TODO: Move run commands to a function to make it less verbose 

import argparse
from collections import defaultdict
from datetime import datetime, timedelta
import json
import logging
import subprocess
import re
import os
import sys
import socket
import nemo_client


LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()

formatter = logging.Formatter(
    fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger('cmp-upgrade-tool')
logger.setLevel(LOGLEVEL)
logger.addHandler(handler)


TOOL_NAME="custom-opscare-openstack-cmp-upgrade-tool"
USER=os.getenv('USER')
CLOUD=os.getenv("CLOUD")
OPENSTACK_EXTRA_ARGS=os.getenv('OPENSTACK_EXTRA_ARGS', 
                            f'--os-auth-type v3token --os-token "{os.getenv("OS_AUTH_TOKEN")}"')

def check_cmp_upgrade_readiness(cmp):
    vms = get_vms_in_host(cmp)
    vms_not_in_shutoff_state = [vm for vm in vms if vm['Status'] != 'SHUTOFF' and not vm['Name'].startswith('healthcheck_SNAT_')]
    if len(vms_not_in_shutoff_state) == 0:
        return True
    else:
        logger.error(f"Node {cmp} has VM(s): {vms_not_in_shutoff_state}")
        return False

def get_vms_in_host(cmp):
    cmd = f"openstack {OPENSTACK_EXTRA_ARGS} server list --all -n -f json --limit 100000000000 --host {cmp}"
    result = subprocess.run(
        cmd,
        shell=True,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    return json.loads(result.stdout)
        
def check_env():
    cmd = ["kubectl", "config", "get-contexts"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if "mcc" not in result.stdout and "mosk" not in result.stdout:
        logger.error(f"Kubernetes context is not set correctly")
        return False
    if os.getenv("CLOUD").replace("_","-") not in os.getenv("OS_AUTH_URL"):
        logger.error(f"CLOUD env var does not match the exported Openstack env")
        return False
    return True
        
def get_az_for_host(host_name, hosts_list):
    host_entry = next(
            (host for host in hosts_list if host['Host'] == host_name),
            None
        )
    return host_entry['Zone'] if host_entry else "AZ_not_assigned"

def get_mosk_cluster_ns():
    cmd = ["kubectl", "--context", f"mcc-{CLOUD}", 'get', 'cluster', '-A', '--no-headers' ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    for line in result.stdout.split("\n"):
        if not 'default' in line and line != '':
            return line.split(" ")[0]

"""

Inventory format: [machine, node, AZ, Rack]
Eg:
['cmp-z01r09b01-01', 'kaas-node-c3a5c58c-ee82-42fd-b1dd-ed90d68b96b2', 'eu-lon-dev1-a', 'z01r09b01']

"""
def get_cmp_inventory():
    logger.info("Gathering machine/node in the cluster")
    cmd = ['kubectl', "--context", f"mcc-{CLOUD}", 'get', 'machine', '-A',  '-o', 'custom-columns=NAME:.metadata.name,INSTANCE:.status.instanceName']
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"kubectl command failed: {result.stderr}")
        return False
    inventory = [' '.join(node.split()).split() for node in result.stdout.split("\n") if 'cmp' in node]

    # Get AZs
    logger.info("Gathering AZs information")
    cmd = f"openstack {OPENSTACK_EXTRA_ARGS} compute service list --long -f json"
        
    result = subprocess.run(
            cmd,
            shell=True,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    
    if result.returncode != 0:
        logger.error(f"openstack command failed: {result.stderr}")
        return False
    azs = json.loads(result.stdout)
    for line in inventory:
        line.append(get_az_for_host(line[1], azs))
        line.append(re.search( r'z\d+r\d+b\d+', line[0]).group())

    logger.debug(inventory)
    return inventory

def create_nodeworkloadlock(cmp):
    lock_obj_yaml = f"""
    apiVersion: lcm.mirantis.com/v1alpha1
    kind: NodeWorkloadLock
    metadata:
        name: {TOOL_NAME}-{cmp}
    spec:
        nodeName: {cmp}
        controllerName: {TOOL_NAME}
    """
    
    logger.info(f"Creating NodeWorkloadLock for {cmp}")

    cmd = ['kubectl',  "--context", f"mosk-{CLOUD}",'apply', '-f', '-']  
    result = subprocess.run(
        cmd,
        input=lock_obj_yaml,     
        capture_output=True,
        text=True                         
    )
    
    if result.returncode != 0:
        logger.error(f"kubectl command failed: {result.stderr}")
        return False
    return result.stdout


def check_nodeworkloadlock(cmp):
    logger.info(f"Checking NodeWorkloadLock for {cmp}")
    cmd = ['kubectl',  "--context", f"mosk-{CLOUD}", 'get', 'nodeworkloadlock', f"{TOOL_NAME}-{cmp}"]  
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True                         
    )
    
    if result.returncode != 0:
        return False
    else:
        return True

def remove_nodeworkloadlock(cmp):
    logger.info(f"Removing NodeWorkloadLock for {cmp}")
    cmd = f"kubectl --context mosk-{CLOUD} delete nodeworkloadlock --grace-period=0 {TOOL_NAME}-{cmp}"
    result = subprocess.run(
        cmd,
        capture_output=True,
        shell=True
    )
    if result.returncode != 0:
        logger.error(f"kubectl command failed: {result.stderr}")
        return False
    else:
        return True

def lock_all_nodes(inventory):
    for node in inventory:
        create_nodeworkloadlock(node[1])

def check_locks_all_nodes(inventory):
    status=True
    for node in inventory:
        if not check_nodeworkloadlock(node[1]):
            logger.error(f"NodeWorkloadLock absent for the node {node[1]}")
            logger.critical("DO NOT START THE UPGRADE")
            status=False
            break
    return status

def rack_release_lock(inventory,rack,unsafe=False):
    logger.info(f"Releasing Locks on rack: {rack}")
    inventory_filtered_by_rack=[row for row in inventory if row[3] == rack]
    logger.debug(inventory_filtered_by_rack)
    for node in inventory_filtered_by_rack:
        if unsafe==True:
            remove_nodeworkloadlock(node[1])
        else:
            if check_cmp_upgrade_readiness(node[1]):
                remove_nodeworkloadlock(node[1])



def rack_silence_alert(inventory,rack):
    logger.info(f"Silencing alert for the rack: {rack}")
    inventory_filtered_by_rack=[row for row in inventory if row[3] == rack]
    logger.debug(inventory_filtered_by_rack)
    status=True
    for node in inventory_filtered_by_rack:
        cmds = [
            f"kubectl --context mosk-{CLOUD} -n stacklight exec sts/prometheus-alertmanager -c prometheus-alertmanager -- amtool --alertmanager.url http://127.0.0.1:9093 silence add -a '{USER}'  -d 2h -c '{TOOL_NAME}: MOSK Rack Upgrade'  'node={node[1]}'", 
            f"kubectl --context mosk-{CLOUD} -n stacklight exec sts/prometheus-alertmanager -c prometheus-alertmanager -- amtool --alertmanager.url http://127.0.0.1:9093 silence add -a '{USER}'  -d 2h -c '{TOOL_NAME}: MOSK Rack Upgrade'  'node_name={node[1]}'", 
            f"kubectl --context mosk-{CLOUD} -n stacklight exec sts/prometheus-alertmanager -c prometheus-alertmanager -- amtool --alertmanager.url http://127.0.0.1:9093 silence add -a '{USER}'  -d 2h -c '{TOOL_NAME}: MOSK Rack Upgrade'  'openstack_hypervisor_hostname=~{node[1]}'" 
        ]
        for cmd in cmds:
            result = subprocess.run(
                cmd,
                capture_output=True,
                shell=True
            )
            if result.returncode != 0:
                logger.error(f"kubectl command failed: {result.stderr}")
                status=status and False
            else:
                status=status and True
    return status

def rack_list_vms(inventory,rack):
    vms=[]
    inventory_filtered_by_rack=[row for row in inventory if row[3] == rack]
    for node in inventory_filtered_by_rack:
        vms.append(get_vms_in_host(node[1]))
    return vms



def rack_enable_disable(inventory,rack,op):
    inventory_filtered_by_rack=[row for row in inventory if row[3] == rack]
    logger.debug(inventory_filtered_by_rack)
    for node in inventory_filtered_by_rack:
        if op == 'disable':
            logger.info(f"Disabling {rack}/{node[1]} for placement")
            cmd = f"openstack {OPENSTACK_EXTRA_ARGS} compute service set --disable --disable-reason='{TOOL_NAME}: {USER}: Preparing the node for maintenance' {node[1]} nova-compute"
        elif op == 'enable':
            logger.info(f"Enabling {rack}/{node[1]} for placement")
            cmd = f"openstack {OPENSTACK_EXTRA_ARGS} compute service set --enable {node[1]} nova-compute"
        else:
            logger.error(f'Unknown operation')
            return False
        result = subprocess.run(
            cmd,
            shell=True,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode != 0:
            logger.error(f"openstack command failed: {result.stderr}")
            return False
    return True


def rack_live_migrate(inventory,rack):
    pass 

def get_vm_info(vm_id):
    cmd = f"openstack {OPENSTACK_EXTRA_ARGS} server show -f json {vm_id}"
        
    result = subprocess.run(
            cmd,
            shell=True,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    
    if result.returncode != 0:
        logger.error(f"openstack command failed: {result.stderr}")
        return False
    
    vm_info = json.loads(result.stdout)
    logger.debug(vm_info)
    return vm_info

def prepare_nemo_host_entry(vm_id, rack, hypervisor):
    vm_dict={}
    vm_info = get_vm_info(vm_id)
    vm_dict["vm_id"]=vm_id
    vm_dict["sd_project"]="Empty"
    vm_dict["sd_component"]="Empty" 
    try:
        vm_dict["fqdn"] = get_reverse_dns(extract_fip(vm_info['addresses'])[0])
        if not vm_dict["fqdn"]:
            logger.debug(f"IP not resolvable on {vm_id}, falling back to VM name")
            vm_dict["fqdn"] = vm_info["name"]
    except (KeyError,IndexError):
        vm_dict["fqdn"] = vm_info["name"]
    project_info = get_project_info(vm_info["project_id"])
    try:
        tags_dict = dict(tag.split('=') for tag in project_info["tags"])
        vm_dict["sd_project"] = tags_dict["sd_project"]
        vm_dict["sd_component"] = tags_dict["sd_component"]
    except KeyError:
        logger.warning(f"Tags do not exist for the vm: {vm_id}")
    vm_dict["rack"]= rack
    vm_dict["hypervisor"]=hypervisor
    return vm_dict

def get_project_info(project_id_or_name):
    cmd = f"openstack {OPENSTACK_EXTRA_ARGS} project show -f json {project_id_or_name}"
        
    result = subprocess.run(
            cmd,
            shell=True,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    
    if result.returncode != 0:
        logger.error(f"openstack command failed: {result.stderr}")
        return False
    
    project_info = json.loads(result.stdout)
    logger.debug(project_info)
    return project_info


def get_reverse_dns(ip):
    try:
        fqdn = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        fqdn = None
    logger.debug(fqdn)
    return fqdn

def get_az_rack_mapping(inventory):
    result = defaultdict(set)
    
    for sublist in inventory:
        key = sublist[2]
        value = sublist[3]
        result[key].add(value)
    result_dict=dict(result)
    other_elements = set().union(*[v for k, v in result_dict.items() if k != 'AZ_not_assigned'])
    result_dict['AZ_not_assigned'].difference_update(other_elements) 
    return result_dict

def get_racks_sorted_by_az(inventory):
    az_rack = sorted(list(set((item[2], item[3]) for item in inventory)))
    logger.debug(f"az_rack= {az_rack}")
    return set([item[1] for item in az_rack])

def get_racks(inventory):
    return sorted(list(set([item[3] for item in inventory])))

def get_nodes_in_rack(inventory,rack):
    return [row for row in inventory if row[3] == rack]

def get_azs(inventory):
    return sorted(set(item[2] for item in inventory if item[2] is not None))

def extract_fip(net_obj):
    ips_starting_with_10 = []
    for network_name, ip_addresses in net_obj.items():
        ips_starting_with_10.extend([ip for ip in ip_addresses if ip.startswith('10.')])

    return ips_starting_with_10

def is_friday_or_weekend(date=None):
    if date is None:
        date = datetime.today()
    elif isinstance(date, str):
        date = datetime.strptime(date, '%Y-%m-%d')
    
    return date.weekday() >= 4

def find_nearest_weekday(date=None):
    """
    Find the nearest date that is not Friday or weekend.
    """
    if date is None:
        date = datetime.today()
    elif isinstance(date, str):
        date = datetime.strptime(date, '%Y-%m-%d')
    
    current_day = date.weekday()
    
    if current_day < 4:  
        return date.date()
    
    days_to_next_weekday = (7 - current_day) % 7

    return (date + timedelta(days=days_to_next_weekday)).date()

def nemo_plan_crs(start_date):
    nemo_config = nemo_client.parse_config()
    inventory = get_cmp_inventory()
    rack_mw_start_date=start_date
    rack_mw_start_time="8:00"
    scheduled_rack_per_day_count=1
    for rack in get_racks(inventory):
        hosts=[]
        for node in get_nodes_in_rack(inventory, rack):
            for vm in get_vms_in_host(node[1]):
                if not vm['Name'].startswith('healthcheck_SNAT_'):
                    logger.info(f"Gathering info on Rack {rack} / VM {vm['ID']}")
                    hosts.append(prepare_nemo_host_entry(vm['ID'],rack, node[1]))
                else:
                    logger.info(f"Skipping healthcheck_SNAT VM Rack {rack} / VM {vm['ID']}")
        
        summary=f"opscare/{CLOUD}/{rack} compute nodes maintenance"
        
        if is_friday_or_weekend(rack_mw_start_date):
            nearest_weekday = find_nearest_weekday(rack_mw_start_date).strftime("%Y-%m-%d")
        else:
            nearest_weekday = rack_mw_start_date
        
        if scheduled_rack_per_day_count == 1:
            rack_mw_start_time = "8:00"
            rack_mw_end_time = "11:00"
        elif scheduled_rack_per_day_count == 2:
            rack_mw_start_time="11:00"
            rack_mw_end_time = "14:00"
        elif scheduled_rack_per_day_count == 3:
            rack_mw_start_time="14:00"
            rack_mw_end_time = "17:00"
        
        r = nemo_client.create_cr(summary, 
                                    f"{nearest_weekday}T{rack_mw_start_time}", 
                                    f"{nearest_weekday}T{rack_mw_end_time}", 
                                    json.dumps(hosts), 
                                    **nemo_config, 
                                    dryrun=False
                                    )
        scheduled_rack_per_day_count+=1
        if scheduled_rack_per_day_count == 4:
            # Reset since we do 3 rack per day
            scheduled_rack_per_day_count = 1
            # Next day
            rack_mw_start_date = (datetime.strptime(nearest_weekday, "%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
        r.close()



def nemo_list_crs(date):
    nemo_config = nemo_client.parse_config()
    r = nemo_client.fetch_crs_list(**nemo_config,on_date=date)
    logger.debug(f"nemo_fetch_crs results = {r.status} {r.reason}")
    crs = json.loads(r.read())
    logger.debug(f"crs = {crs}")
    r.close()
    total_crs_of_the_date = int(crs['count'])
    logger.debug(f'total_crs_of_the_date = {total_crs_of_the_date}')
    crs_of_the_date = [
        item for item in crs['results'] 
        if item['summary'].startswith(f'opscare/{CLOUD}')
    ]
    logger.debug(f"crs_for_the_date = {crs_of_the_date}")
    return crs_of_the_date

def nemo_process_crs():
    today_date = datetime.today().strftime('%Y-%m-%d')
    nemo_list_crs(today_date)


def nemo_freeze_racks():
    pass

def main():
    parser = argparse.ArgumentParser(description="MOSK Compute upgrade Tool")
    
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    lock_parser = subparsers.add_parser('lock-all-nodes', help='Lock all nodes')
    check_parser = subparsers.add_parser('check-locks', help='Check locks')
    list_parser = subparsers.add_parser('list-vms', help='List VMs')
    
    rack_parser = subparsers.add_parser('rack-list-vms', help='List VMs on a specific rack')
    rack_parser.add_argument('rack', type=str, help='Rack name')
    
    release_parser = subparsers.add_parser('rack-release-lock', help='Release lock on a rack')
    release_parser.add_argument('rack', type=str, help='Rack name')
    
    disable_parser = subparsers.add_parser('rack-disable', help='Disable a rack')
    disable_parser.add_argument('rack', type=str, help='Rack name')
    
    enable_parser = subparsers.add_parser('rack-enable', help='Enable a rack')
    enable_parser.add_argument('rack', type=str, help='Rack name')
    
    migrate_parser = subparsers.add_parser('rack-live-migrate', help='Live migrate VMs in a rack')
    migrate_parser.add_argument('rack', type=str, help='Rack name')
    
    silence_parser = subparsers.add_parser('rack-silence', help='Silence notifications on a rack')
    silence_parser.add_argument('rack', type=str, help='Rack name')
    
    nemo_plan_crs_parser = subparsers.add_parser('nemo-plan-crs', help='Create the CRs in Nemo')
    nemo_plan_crs_parser.add_argument("startdate", type=str, help="A date time when the CRs start")

    nemo_process_crs_parser = subparsers.add_parser('nemo-process-crs', help="Process Nemo's CRs scheduled now")
    
    nemo_freeze_racks_parser = subparsers.add_parser('nemo-freeze-racks', help="Process Nemo's CRs scheduled now")

    args = parser.parse_args()
    
    if args.command == 'lock-all-nodes':
        print("==> Locking all nodes...")
    elif args.command == 'check-locks':
        print("==> Checking locks...")
    elif args.command == 'list-vms':
        print("==> Listing VMs...")
    elif args.command == 'rack-list-vms':
        print(f"==> Listing VMs in rack: {args.rack}")
    elif args.command == 'rack-release-lock':
        print(f"==> Releasing lock on rack: {args.rack}")
    elif args.command == 'rack-disable':
        print(f"==> Disabling rack: {args.rack}")
    elif args.command == 'rack-enable':
        print(f"==> Enabling rack: {args.rack}")
    elif args.command == 'rack-live-migrate':
        print(f"==> Migrating VMs in rack: {args.rack}")
    elif args.command == 'rack-silence':
        print(f"==> Silencing notifications on rack: {args.rack}")
    elif args.command == 'nemo-plan-crs':
        print(f"==> Creating CRs on Nemo")
        nemo_plan_crs(args.startdate)
    elif args.command == 'nemo-process-crs':
        print(f"==> Processing Nemo's CRs scheduled now")
        nemo_process_crs()
    elif args.command == 'nemo-freeze-rack':
        print(f"==> Freezing racks for upcoming changes in Nemo")
        nemo_freeze_racks()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
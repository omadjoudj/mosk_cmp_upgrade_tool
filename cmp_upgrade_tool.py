#!/usr/bin/python3
# Customization owner: omadjoudj

## NOTE:

# openstack client and kubectl are used directly instead of corresponding Python libraries to reduce the dependencies on external libraries

# This script is used by trusted users, data validation was skipped

#TODO: Move run commands to a function to make it less verbose 

import argparse
import json
import logging
import subprocess
import re
import os
import sys
import socket

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
        logging.error(f"Node {cmp} has VM(s): {vms_not_in_shutoff_state}")
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
        logging.error(f"Kubernetes context is not set correctly")
        return False
    if os.getenv("CLOUD").replace("_","-") not in os.getenv("OS_AUTH_URL"):
        logging.error(f"CLOUD env var does not match the exported Openstack env")
        return False
    return True
        
def get_az_for_host(host_name, hosts_list):
    return next((host['Zone Name'] for host in hosts_list if host['Host Name'] == host_name), None)

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
    logging.info("Gathering machine/node in the cluster")
    cmd = ['kubectl', "--context", f"mcc-{CLOUD}", 'get', 'machine', '-A',  '-o', 'custom-columns=NAME:.metadata.name,INSTANCE:.status.instanceName']
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        logging.error(f"kubectl command failed: {result.stderr}")
        return False
    inventory = [' '.join(node.split()).split() for node in result.stdout.split("\n") if 'cmp' in node]

    # Get AZs
    logging.info("Getting AZs information")
    cmd = f"openstack {OPENSTACK_EXTRA_ARGS} availability zone list --long -f json"
        
    result = subprocess.run(
            cmd,
            shell=True,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    
    if result.returncode != 0:
        logging.error(f"openstack command failed: {result.stderr}")
        return False
    azs = json.loads(result.stdout)
    for line in inventory:
        line.append(get_az_for_host(line[1], azs))
        line.append(re.search( r'z\d+r\d+b\d+', line[0]).group())

    logging.debug(inventory)
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
    
    logging.info(f"Creating NodeWorkloadLock for {cmp}")

    cmd = ['kubectl',  "--context", f"mosk-{CLOUD}",'apply', '-f', '-']  
    result = subprocess.run(
        cmd,
        input=lock_obj_yaml,     
        capture_output=True,
        text=True                         
    )
    
    if result.returncode != 0:
        logging.error(f"kubectl command failed: {result.stderr}")
        return False
    return result.stdout


def check_nodeworkloadlock(cmp):
    logging.info(f"Checking NodeWorkloadLock for {cmp}")
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
    logging.info(f"Removing NodeWorkloadLock for {cmp}")
    cmd = f"kubectl --context mosk-{CLOUD} delete nodeworkloadlock --grace-period=0 {TOOL_NAME}-{cmp}"
    result = subprocess.run(
        cmd,
        capture_output=True,
        shell=True
    )
    if result.returncode != 0:
        logging.error(f"kubectl command failed: {result.stderr}")
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
            logging.error(f"NodeWorkloadLock absent for the node {node[1]}")
            logging.critical("DO NOT START THE UPGRADE")
            status=False
            break
    return status

def rack_release_lock(inventory,rack,unsafe=False):
    logging.info(f"Releasing Locks on rack: {rack}")
    inventory_filtered_by_rack=[row for row in inventory if row[3] == rack]
    logging.debug(inventory_filtered_by_rack)
    for node in inventory_filtered_by_rack:
        if unsafe==True:
            remove_nodeworkloadlock(node[1])
        else:
            if check_cmp_upgrade_readiness(node[1]):
                remove_nodeworkloadlock(node[1])



def rack_silence_alert(inventory,rack):
    logging.info(f"Silencing alert for the rack: {rack}")
    inventory_filtered_by_rack=[row for row in inventory if row[3] == rack]
    logging.debug(inventory_filtered_by_rack)
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
                logging.error(f"kubectl command failed: {result.stderr}")
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
    logging.debug(inventory_filtered_by_rack)
    for node in inventory_filtered_by_rack:
        if op == 'disable':
            logging.info(f"Disabling {rack}/{node[1]} for placement")
            cmd = f"openstack {OPENSTACK_EXTRA_ARGS} compute service set --disable --disable-reason='{TOOL_NAME}: {USER}: Preparing the node for maintenance' {node[1]} nova-compute"
        elif op == 'enable':
            logging.info(f"Enabling {rack}/{node[1]} for placement")
            cmd = f"openstack {OPENSTACK_EXTRA_ARGS} compute service set --enable {node[1]} nova-compute"
        else:
            logging.error(f'Unknown operation')
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
            logging.error(f"openstack command failed: {result.stderr}")
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
        logging.error(f"openstack command failed: {result.stderr}")
        return False
    
    vm_info = json.loads(result.stdout)
    logging.debug(vm_info)
    return vm_info

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
        logging.error(f"openstack command failed: {result.stderr}")
        return False
    
    project_info = json.loads(result.stdout)
    logging.debug(project_info)
    return project_info


def get_reverse_dns(ip):
    try:
        fqdn = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        fqdn = None
    logging.debug(fqdn)
    return fqdn


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
    
    #node_release_parser = subparsers.add_parser('node-release-lock', help='Release lock on a node')
    #node_release_parser.add_argument('node', type=str, help='Node name')
    
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
    #elif args.command == 'node-release-lock':
    #    print(f"Releasing lock on node: {args.node}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
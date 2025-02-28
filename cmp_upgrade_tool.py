#!/usr/bin/python3
# Customization owner: omadjoudj

## NOTE:

# openstack client and kubectl are used directly instead of corresponding Python libraries to reduce the dependencies on external libraries

# This script is used by trusted users, data validation was skipped

import argparse
import json
import logging
import subprocess
import re
import os
import socket

from pprint import pprint

TOOL_NAME="custom-opscare-openstack-cmp-upgrade-tool"
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
    #TODO: Move this to a function to make it less verbose 
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
    cmd = ['kubectl',  "--context", f"mosk-{CLOUD}", 'get', 'nodeworkloadlock', f"{TOOL_NAME}-{cmp}"]  
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True                         
    )
    
    if result.returncode != 0:
        logging.error(f"kubectl command failed: {result.stderr}")
        return False
    else:
        return True

def remove_nodeworkloadlock(cmp):
    logging.info(f"Removing NodeWorkloadLock for {cmp}")
    cmd = ['kubectl',  "--context", f"mosk-{CLOUD}", 'delete', 'nodeworkloadlock', '--grace-period=0', f"{TOOL_NAME}-{cmp}"]  
    result = subprocess.run(
        cmd,
        capture_output=True,
        shell=True
    )
    pprint(result)
    if result.returncode != 0:
        logging.error(f"kubectl command failed: {result.stderr}")
        return False
    else:
        return True

def node_safe_release_lock():
    pass

def lock_all_nodes():
    pass

def check_locks_all_nodes():
    pass

def rack_silence_alert():
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
    # Create the main ArgumentParser object
    parser = argparse.ArgumentParser(description="MOSK Compute upgrade Tool")
    
    # Add global options (if any)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Define parsers for each command
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
    
    # Parse arguments
    args = parser.parse_args()
    
    # Handle command execution
    if args.command == 'lock-all-nodes':
        print("Locking all nodes...")
    elif args.command == 'check-locks':
        print("Checking locks...")
    elif args.command == 'list-vms':
        print("Listing VMs...")
    elif args.command == 'rack-list-vms':
        print(f"Listing VMs in rack: {args.rack}")
    elif args.command == 'rack-release-lock':
        print(f"Releasing lock on rack: {args.rack}")
    elif args.command == 'rack-disable':
        print(f"Disabling rack: {args.rack}")
    elif args.command == 'rack-enable':
        print(f"Enabling rack: {args.rack}")
    elif args.command == 'rack-live-migrate':
        print(f"Migrating VMs in rack: {args.rack}")
    elif args.command == 'rack-silence':
        print(f"Silencing notifications on rack: {args.rack}")
    #elif args.command == 'node-release-lock':
    #    print(f"Releasing lock on node: {args.node}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
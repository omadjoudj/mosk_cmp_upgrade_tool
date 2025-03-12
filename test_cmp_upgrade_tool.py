import pytest
import cmp_upgrade_tool
import re
from pprint import pprint

"""
def test_func_get_mosk_cluster_ns():
    r = cmp_upgrade_tool.get_mosk_cluster_ns()
    assert r == "lon1-dev-mos001"

def test_func_get_cmp_inventory():
    r = cmp_upgrade_tool.get_cmp_inventory()
    for l in r:
        assert ('cmp' in l[0])
    for l in r:
        assert ('osd' not in l[0])
    for l in r:
        assert ('ctl' not in l[0])

def test_get_vms_in_host():
    cmp="kaas-node-09624872-54dd-4ca8-99dd-18368c964c17"
    vms=cmp_upgrade_tool.get_vms_in_host(cmp)
    pprint(vms)
    assert any(vm['Name'] == ("healthcheck_SNAT_%s" % cmp) for vm in vms)
def test_func_check_cmp_upgrade_readiness():
    cmp="kaas-node-09624872-54dd-4ca8-99dd-18368c964c17"
    assert cmp_upgrade_tool.check_cmp_upgrade_readiness(cmp) == False

def test_get_vm_info():
    vm_id="0e330637-00ee-4a64-82cb-ba34683bd45e"
    cmp_upgrade_tool.get_vm_info(vm_id)

def test_get_project_info():
    prj_name="threekvm-2"
    cmp_upgrade_tool.get_project_info(prj_name)

def test_get_reverse_dns():
    fqdn_to_ip = {
        '8.8.8.8': 'dns.google',
        '1.1.1.1': 'one.one.one.one'
    }
    for ip in fqdn_to_ip.keys():
        assert cmp_upgrade_tool.get_reverse_dns(ip) == fqdn_to_ip[ip]


def test_create_nodeworkloadlock():
    cmp="kaas-node-09624872-54dd-4ca8-99dd-18368c964c17"
    cmp_upgrade_tool.create_nodeworkloadlock(cmp)
    assert cmp_upgrade_tool.check_nodeworkloadlock(cmp)


def test_remove_nodeworkloadlock():
    cmp="kaas-node-09624872-54dd-4ca8-99dd-18368c964c17"
    cmp_upgrade_tool.remove_nodeworkloadlock(cmp)
    assert cmp_upgrade_tool.check_nodeworkloadlock(cmp) == False

def test_lock_all_nodes():
    inventory = cmp_upgrade_tool.get_cmp_inventory()
    cmp="kaas-node-09624872-54dd-4ca8-99dd-18368c964c17"
    assert(cmp_upgrade_tool.check_locks_all_nodes(inventory)==False)
    cmp_upgrade_tool.lock_all_nodes(inventory)
    assert(cmp_upgrade_tool.check_locks_all_nodes(inventory))
    cmp_upgrade_tool.remove_nodeworkloadlock(cmp)
    assert(cmp_upgrade_tool.check_locks_all_nodes(inventory)==False)


def test_rack_enable_disable():
    inventory = cmp_upgrade_tool.get_cmp_inventory()
    rack="z01r09b01"
    assert cmp_upgrade_tool.rack_enable_disable(inventory,rack,'disable')
    assert cmp_upgrade_tool.rack_enable_disable(inventory,rack,'enable')

def test_rack_silence_alert():
    inventory = cmp_upgrade_tool.get_cmp_inventory()
    rack="z01r09b01"
    assert cmp_upgrade_tool.rack_silence_alert(inventory,rack)

def test_rack_release_lock():
    inventory = cmp_upgrade_tool.get_cmp_inventory()
    rack="z01r09b01"
    cmp_upgrade_tool.rack_release_lock(inventory,rack)

def test_rack_release_lock_on_all_racks():
    inventory = cmp_upgrade_tool.get_cmp_inventory()
    for rack in list(dict.fromkeys([row[3] for row in inventory])):
        cmp_upgrade_tool.rack_release_lock(inventory,rack,unsafe=True)

    assert(cmp_upgrade_tool.check_locks_all_nodes(inventory)==False)

def test_rack_list_vms():
    inventory = cmp_upgrade_tool.get_cmp_inventory()
    rack="z01r09b01"
    print(f"==> VMs in rack {rack}")
    pprint(cmp_upgrade_tool.rack_list_vms(inventory,rack))
"""

def test_get_racks_sorted_by_az():
    inventory = cmp_upgrade_tool.get_cmp_inventory()
    racks = cmp_upgrade_tool.get_racks_sorted_by_az(inventory)
    print(f"racls= {racks}")
    print(f"len(racls) = {len(racks)}")
    pprint(inventory)
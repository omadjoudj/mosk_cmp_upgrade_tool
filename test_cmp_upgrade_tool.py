import pytest
import cmp_upgrade_tool
import re

""" def test_func_get_mosk_cluster_ns():
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
    assert any(vm['Name'] == ("healthcheck_SNAT_%s" % cmp) for vm in vms) """

def test_func_check_cmp_upgrade_readiness():
    cmp="kaas-node-09624872-54dd-4ca8-99dd-18368c964c17"
    assert cmp_upgrade_tool.check_cmp_upgrade_readiness(cmp) == False
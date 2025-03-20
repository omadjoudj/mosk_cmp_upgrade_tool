#!/bin/bash

if [ $# -lt 1 ]; then
    echo "No enough args"
    exit 1
fi

while true;
do
    for arg in "$@"
    do
        echo "======================================"
        echo "Syncing Nemo CRs for $arg"
        cloud_region_name="$( echo $arg | cut -d- -f2 | tr '_' '-')"
        eval $(bkos-creds --region $cloud_region_name --project admin --env)
        export CLOUD=$( echo $cloud_region_name | tr '-' '_')
        echo "CLOUD=$CLOUD"
        ./cmp_upgrade_tool.py nemo-refresh-crs
    done
    sleep 10
done

"""
Copyright (c) 2020 VMware, Inc.

Modified for NetBox by Ryan Hinson (@rnhinson)

This product is licensed to you under the Apache License, Version 2.0 (the "License").
You may not use this product except in compliance with the License.

This product may include a number of subcomponents with separate copyright notices
and license terms. Your use of these subcomponents is subject to the terms and
conditions of the subcomponent's license, as noted in the LICENSE file.
"""

import requests
from vra_ipam_utils.ipam import IPAM
import logging
from requests.packages import urllib3

def handler(context, inputs):

    ipam = IPAM(context, inputs)
    IPAM.do_deallocate_ip = do_deallocate_ip

    return ipam.deallocate_ip()

def do_deallocate_ip(self, auth_credentials, cert):
    netbox_url = self.inputs["endpoint"]["endpointProperties"]["hostName"]
    username = auth_credentials["privateKeyId"] # not needed for NetBox, but required for vRA IPAM plugin
    token = auth_credentials["privateKey"]
    deallocation_result = []
    for deallocation in self.inputs["ipDeallocations"]:
        deallocation_result.append(deallocate(self.inputs["resourceInfo"], self.inputs["endpoint"], deallocation, auth_credentials, netbox_url, token))

    assert len(deallocation_result) > 0
    return {
        "ipDeallocations": deallocation_result
    }

def deallocate(resource, endpoint, deallocation, auth_credentials, netbox_url, token):

    try:
        ignore_ssl = str(endpoint["endpointProperties"]["ignore_ssl"])
        if ignore_ssl == "true":
            urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)
            verify = False
        else:
            verify = True
    except Exception as e:
        raise e

    ip_range_id = deallocation["ipRangeId"]
    ip = deallocation["ipAddress"]
    resource_id = resource["id"]

    headers = {
      "Authorization": f"Token {token}",
      "accept": "application/json",
      "Content-Type": "application/json"
    }

    logging.info(f"Deallocating ip {ip} from range {ip_range_id}")

    ip_get = requests.get(f"{netbox_url}/api/ipam/ip-addresses/?address={ip}", headers=headers, verify=verify)
    results = ip_get.json()["results"]
    ips = []

    for result in results:
      payload = {
        "address": str(result["address"]),
        "id": str(result["id"])
      }
      ips.append(payload)
    delete = requests.delete(f"{netbox_url}/api/ipam/ip-addresses/", json=ips, headers=headers, verify=verify)
    if delete.status_code != 204:
      error = logging.error(f"IP deletion from Netbox failed with status code: {delete.status_code}")
      return error

    return {
        "ipDeallocationId": deallocation["id"],
        "message": "Success"
    }

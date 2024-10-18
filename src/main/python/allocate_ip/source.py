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
import os
import ipaddress
from requests.packages import urllib3

def handler(context, inputs):

    ipam = IPAM(context, inputs)
    IPAM.do_allocate_ip = do_allocate_ip

    return ipam.allocate_ip()

def do_allocate_ip(self, auth_credentials, cert):
    username = auth_credentials["privateKeyId"] # not needed for NetBox, but required for vRA IPAM plugin
    token = auth_credentials["privateKey"]

    allocation_result = []
    try:
        resource = self.inputs["resourceInfo"]
        for allocation in self.inputs["ipAllocations"]:
            allocation_result.append(allocate(resource, auth_credentials, allocation, self.context, self.inputs["endpoint"]))
    except Exception as e:
        try:
            rollback(allocation_result, auth_credentials, self.inputs["endpoint"])
        except Exception as rollback_e:
            logging.error(f"Error during rollback of allocation result {str(allocation_result)}")
            logging.error(rollback_e)
        raise e

    assert len(allocation_result) > 0
    return {
        "ipAllocations": allocation_result
    }

def allocate(resource, auth_credentials, allocation, context, endpoint):

    last_error = None
    for range_id in allocation["ipRangeIds"]:

        logging.info(f"Allocating from range {range_id}")
        try:
            logging.warning(str(range_id))
            return allocate_in_range(range_id, auth_credentials, resource, allocation, context, endpoint)
        except Exception as e:
            last_error = e
            logging.error(f"Failed to allocate from range {range_id}: {str(e)}")

    logging.error("No more ranges. Raising last error")
    raise last_error


def allocate_in_range(range_id, auth_credentials, resource, allocation, context, endpoint):

    try:
        ignore_ssl = str(self.inputs["endpoint"]["endpointProperties"]["ignore_ssl"])
        if ignore_ssl == "true":
            urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)
            verify = False
        else:
            verify = True
    except Exception as e:
        raise e

    token = auth_credentials["privateKey"]
    netbox_url = endpoint["endpointProperties"]["hostName"]
    netbox_object = endpoint["endpointProperties"]["netboxObject"]
    headers = {
      "Authorization": f"Token {token}",
      "accept": "application/json",
      "Content-Type": "application/json"
      }
    ips = []

    if netbox_object == "ip-ranges":
      response = requests.get(f"{netbox_url}/api/ipam/ip-ranges/{str(range_id)}", headers=headers, verify=verify)
      r = response.json()
    else:
      response = requests.get(f"{netbox_url}/api/ipam/prefixes/{str(range_id)}", headers=headers, verify=verify)
      r = response.json()


    if str(r['id']) != str(range_id): # ensure we have the correct prefix
       p_error = logging.error(f"Range {str(r['id'])} does not match given ipRangeId: {str(range_id)}")
       return p_error # error if the prefix doesn't match the range_id from vRA

    addresses = requests.get(f"{str(r['url'])}/available-ips/?limit=5", headers=headers, verify=verify)

    for address in addresses.json():
      network = (ipaddress.ip_interface(str(address['address']))).network # get parent prefix from ip address object
      ip = str(address['address']).split('/')[0] # get ip address without cidr prefix
"""
      uncomment and replace to have vRA ping addresses before provisioning.
      - This could prevent IP conflicts with addresses that exist but are not tracked in NetBox.
      - vRA instance will need to be allowed to send ICMP to all networks in the environment.

      #ping = os.system("ping -c 1 -W 1 " + ip + ">/dev/null")
      #if (str(ip) != str(network[1])) and (ping != 0):
"""
      if (str(ip) != str(network[1])): # replace here, see above
          payload = {
            "family": 4,
            "address": str(address['address']),
            "vrf": str(address['vrf']['id']),
            "dns_name": str(resource['name'])
            }
          post_ip = requests.post(f"{str(netbox_url)}/api/ipam/ip-addresses/", json=payload, headers=headers, verify=verify)
          if post_ip.status_code == 201:
            ips.append(ip)
          else:
            error = logging.error(f"Failed to provision IP address with status code: {post_ip.status_code}")
            return error
      if ips != []:
        break

    result = {
      "ipAllocationId": allocation["id"],
      "ipRangeId": str(range_id),
      "ipVersion": "IPv4"
    }
    result["ipAddresses"] = ips
    result["properties"] = {"customPropertyKey1": "customPropertyValue1"}

    return result

## Rollback any previously allocated addresses in case this allocation request contains multiple ones and failed in the middle
def rollback(allocation_result, auth_credentials, endpoint):

    ignore_ssl = endpoint["endpointProperties"]["ignore_ssl"]
    if ignore_ssl == "true":
      urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)
      verify = False
    else:
      verify = True

    token = auth_credentials["privateKey"]
    netbox_url = endpoint["endpointProperties"]["hostName"]
    headers = {
      "Authorization": f"Token {token}",
      "accept": "application/json",
      "Content-Type": "application/json"
    }

    for allocation in reversed(allocation_result):
        logging.info(f"Rolling back allocation {str(allocation)}")
        ipAddresses = allocation.get("ipAddresses", None)

        for ipAddress in ipAddresses:
          ip = requests.get(f"{netbox_url}/api/ipam/ip-addresses/?address={ipAddress}", headers=headers, verify=verify)
          results = ip.json()["results"]
          ips = []

          for result in results:
            payload = {
              "address": str(result["address"]),
              "id": str(result["id"])
            }
            ips.append(payload)
          print(ips)
          delete = requests.delete(f"{netbox_url}/api/ipam/ip-addresses/", json=ips, headers=headers, verify=verify)
          print(delete.json())
          if delete.status_code != 204:
            e = logging.error(f"IP Delete failed with status code: {delete.status_code}")
            return e

    return

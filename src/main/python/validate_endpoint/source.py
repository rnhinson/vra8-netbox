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
from requests.packages import urllib3
from vra_ipam_utils.ipam import IPAM
from vra_ipam_utils.exceptions import InvalidCertificateException
import logging

def handler(context, inputs):

    ipam = IPAM(context, inputs)
    IPAM.do_validate_endpoint = do_validate_endpoint

    return ipam.validate_endpoint()

def do_validate_endpoint(self, auth_credentials, cert):

    try:
        ignore_ssl = self.inputs["endpointProperties"]["ignore_ssl"]
        if ignore_ssl == "true":
            urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)
            verify = False
        else:
            verify = True
    except Exception as e:
        raise e

    netbox_url = self.inputs["endpointProperties"]["hostName"]
    username = auth_credentials["privateKeyId"] # not needed for NetBox, but required for vRA IPAM plugin
    token = auth_credentials["privateKey"]

    try:
        response = requests.get(f"{netbox_url}/api", verify=verify, headers={"Authorization": f"Token {token}"})

        if response.status_code == 200:
            return {
                "message": "Validated successfully",
                "statusCode": "200"
            }
        elif response.status_code == 401:
            logging.error(f"Invalid credentials error: {str(response.content)}")
            raise Exception(f"Invalid credentials error: {str(response.content)}")
        else:
            raise Exception(f"Failed to connect: {str(response.content)}")
    except Exception as e:
        """ In case of SSL validation error, a InvalidCertificateException is raised.
            So that the IPAM SDK can go ahead and fetch the server certificate
            and display it to the user for manual acceptance.
        """
        if "SSLCertVerificationError" in str(e) or "CERTIFICATE_VERIFY_FAILED" in str(e) or 'certificate verify failed' in str(e):
            raise InvalidCertificateException("certificate verify failed", self.inputs["endpointProperties"]["hostName"], 443) from e

        raise e

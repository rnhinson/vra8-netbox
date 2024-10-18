
# vra8-netbox

This is a [Third-Party IPAM Provider for VMware Aria Automation](https://developer.broadcom.com/sdks/vmware-aria-automation-third-party-ipam-sdk/latest) (formerly VMware Realize Automation) that integrates with the [Netbox](https://netboxlabs.com) DCIM/IPAM platform.

This first iteration is pretty rudimentary, but it is reliable. Feel free to add or request features.
See the README_sdk.md for original SDK docs, troubleshooting, and developer info.

Special thanks to @jbowdre's blog about his phpIPAM integration: https://runtimeterror.dev/integrating-phpipam-with-vrealize-automation-8. He helped fill in some gaps where other docs could not.

## Features

- Support for `prefixes` or `ip-ranges` NetBox objects.
- Provision IP Addresses via Cloud Assembly templates.
- Configure IP Ranges for imported cloud account networks.
- (Optional) Prevent IP Conflicts with addresses not tracked in NetBox.


## Package

### build requirements
- Docker
- Apache Maven
- Java 8
- Python 3
### environment requrements
- NetBox 3.6.X+ Installation
- VMware Aria Automation 8.14+

### Build Package Locally
Per VMware (README_vmw.md), the provider can be packaged via:
```bash
sudo mvn package -PcollectDependencies
```
Note: If you're on linux you should add the `-Duser.id=${UID}` parameter.

Building the package for the first time should include the `-PcollectDependencies` parameter, but subsequent runs should only require this flag if new Python packages were added.


## Aria Automation Installation
1. Navigate to `Assembler` > `Infrastructure` > `Connections` > `Integrations`
2. Select `+ Add Integration`
3. Select `IPAM`
4. Select `Manage IPAM Providers` > `Import Provider Package`
5. Upload the `netbox.zip` file
6. Select `Complete`
7. Click in `Search for IPAM Providers` and select `NetBox`
8. Enter the following details:
- `NetBox Username`
    - vRA requires the `privateKeyId` field to be populated
    - The IPAM provider is not actually using this for anything
- `NetBox API Key`
    - Service account is recommended.
- `NetBox URL`
    - ex. `https://netbox.domain.com`
- `Netbox Tag`
    - NetBox tag to track vRA managed objects.
- `NetBox Object`
    - Select either `prefixes` or `ip-ranges`
    - These correspond to the `/api/ipam/` API endpoints.
- `NetBox Site`
    - Enter site `name` or `ID`.
- `Ignore SSL`
    - Sets `verify` Python `requests` parameter
    - Disables the `urllib3.exceptions.InsecureRequestWarning`
        - (but seriously, it's 2024, get a cert)

## License

[Apache License, 2.0](https://www.apache.org/licenses/LICENSE-2.0)

## To Do

- Docs
- Reduce Integration Validation requirements
- Dynamic tagging/site inputs

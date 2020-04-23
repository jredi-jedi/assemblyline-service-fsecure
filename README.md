# FSecure Service

This Assemblyline services interfaces with [FSecure Internet Gatekeeper's](https://help.f-secure.com/product.html#business/igk/5.40/en) icap proxy.

**NOTE**: This service **requires you to buy** a licence. It also **requires you to install** gatekeeper on a separate machine/VM. It is **not** preinstalled during a default installation

## Execution

The service uses our generic icap interface to send files to the proxy server for analysis and report the results back to the user.

## Installation of FSecure GK

To install FSecure GK you can follow our detailed documentation [here](docs/icap_installation_notes.md).

## Licensing

The service was developed with Fsecure GK Version: 5.40

Contact your FSecure reseller to get access to the licence you need for your deployment: [https://www.f-secure.com/en/web/business_global/partners/locator](https://www.f-secure.com/en/web/business_global/partners/locator)
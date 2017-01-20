# FSecure Service

This Assemblyline services interfaces with [FSecure Internet Gatekeeper's](https://www.f-secure.com/en/web/business_global/products/internet-gatekeeper) icap proxy.

**NOTE**: This service **requires you to buy** any licence. It also **requires you to install** gatekeeper on a seperate machine/VM. It is **not** preinstalled during a default installation

## Execution

The service use our generic icap interface to send the file to the proxy server for analysis and report the results back to the user.

## Installation of FSecure GK

To install FSecure GK you can follow our detailled documentation [here](icap_installation/install_notes.md).

## Updates

This service support auto-update in both online and offline environment. This is configurable in the service config.

## Licensing

The service was developed with Fsecure GK Version: 5.40

Contact your FSecure reseller to get access to the proper licence you need for your deployment: [https://www.f-secure.com/en/web/business_global/partners/locator](https://www.f-secure.com/en/web/business_global/partners/locator)
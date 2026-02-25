# smART Sketcher 2.0 - Bluetooth Authentication Bypass

**CVE-2026-0842** | Missing Authentication on BLE Interface

## Overview

The smART Sketcher 2.0 is a Bluetooth-enabled toy projector that lets kids trace images. It has no authentication on its Bluetooth connection - anyone within range can connect and push images to the device without pairing or notification.

## Demo

![Bluetooth Shell](bt-shell.gif)

![Image Upload](image-upload.gif)

## The Issue

- Device broadcasts as "smART Sketcher 2.0" over Bluetooth
- No pairing required to connect
- No authentication to send commands or images
- No notification when someone connects
- Works from 30+ feet away

This means anyone in an apartment building, park, or public space can push content to a child's toy without the parent knowing.

## Usage
```bash
pip install bleak pillow
python bt_shell.py          # interactive bluetooth shell
python upload_image.py image.jpg   # upload an image
```

## Disclosure

Vendor was contacted but did not respond. Full writeup: 

**CWE-306** | [CVE Record](https://www.cve.org/CVERecord?id=CVE-2026-0842)
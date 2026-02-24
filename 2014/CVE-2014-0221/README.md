# OpenSSL_DTLS_CVE_2014_0221
OpenSSL DTLS CVE-2014-0221 Remote Denial 

## DTLS (Datagram Transport Layer Security) 란?

데이터그램 전송 계층 보안. *물리 층

TCP 계층 데이터그램 지원 : TLS   
UDP 계층 데이터그램 지원 : DTLS : HandShake 프로세스의 적절한 수정을 통해 키 교환, 인증, 보안 매개변수 설정 등을 처리, 타임아웃 및 재전송을 통해 비연결성적 특성을 가진 UDP의 안정적인 보안 통신을 지원   
    
DTLS는 Datagram Transport Layer Security의 준말로, UDP(User Datagram Protocol) 기반의 통신에서 보안을 제공하기 위한 프로토콜입니다. 
TLS(Transport Layer Security)는 TCP(Transmission Control Protocol) 기반의 통신에서 보안을 제공하는 데 주로 사용되지만, UDP는 연결 지향적이지 않고 패킷 기반의 프로토콜이기 때문에 TLS를 그대로 적용하기에는 어려움이 있습니다.
이러한 UDP 기반의 통신에서 보안을 제공하기 위해 DTLS가 설계되었습니다.    

DTLS는 TLS의 기본 구조와 매우 유사하지만, 몇 가지 주요 차이점이 있습니다:    

데이터그램 지원: DTLS는 데이터그램 기반 프로토콜인 UDP에 적합하도록 설계되었습니다. TLS는 연결 지향적인 TCP에 최적화되어 있어서, 이를 UDP에 적용하기 위해 데이터그램 단위로 작동할 수 있도록 개조되었습니다.      
Handshake 프로세스의 적절한 수정: DTLS는 TLS와 마찬가지로 Handshake 프로세스를 사용하여 통신의 인증, 키 교환, 보안 매개변수 설정 등을 처리합니다. 그러나 UDP의 특성상 패킷의 손실이나 순서의 변화가 발생할 수 있기 때문에, 이러한 상황에 대응할 수 있는 메커니즘이 DTLS에 추가되었습니다.     
타임아웃 및 재전송: DTLS는 패킷의 손실이나 재전송이 필요할 때를 대비하여 타임아웃 및 재전송 메커니즘을 포함하고 있습니다. 이는 UDP의 비연결성 특성을 보완하여 안정적인 보안 통신을 가능하게 합니다.     
보안 측면에서의 고려: DTLS는 TLS와 동일한 보안 프로토콜을 사용하여 데이터의 기밀성, 무결성, 인증을 보장합니다. 따라서 UDP 기반의 애플리케이션에서도 안전하게 데이터를 전송할 수 있습니다.     
DTLS는 주로 VoIP(음성 통화), 멀티미디어 스트리밍, 게임 서버 등에서 UDP를 사용하는 환경에서 보안을 제공하는 데 활용됩니다.       

## 그렇다면 OpenSSL DTLS 취약점

왜 OpenSSL 인가 :  DTLS 란 : UDP 기반 TLS, DTLS 1.0은 OpenSSL 에서 구현되었음

조작된 핸드셰이크 전송을 통한 중간자(MITM) 공격으로 전송데이터를 복호화하고 서버/클라이언트 간 전송 데이터의 조작이 가능한 취약점 (CVE-2014-0224)    
비정상적인 DTLS 핸드셰이크를 OpenSSL DTLS 클라이언트에 전송하여 서비스 거부 공격이 가능한 취약점 (CVE-2014-0221)   
비정상적인 DTLS 프래그먼트를 OpenSSL DTLS 클라이언트 또는 서버에 전송하여 임의코드 실행이 가능한 취약점 (CVE-2014-0195)    
do_ssl3_write 함수의 결함으로 인해 임의코드 실행이 가능한 취약점 (CVE-2014-0198)   
해당 취약점은 OpenSSL 1.0.0과 1.0.1에서 SSL_MODE_RELEASE_BUFFERS 옵션이 활성화되었을 때 발생 (해당 옵션은 기본적으로 비활성 상태임)    
ssl3_read_bytes 함수의 경쟁 상태(race condition)으로 인해 공격자가 세션에 데이터를 주입시키거나 서비스 거부 공격이 가능한 취약점 (CVE-2010-5298)    
해당 취약점은 OpenSSL 1.0.0과 1.0.1을 사용하는 멀티쓰레드 어플리케이션에서 SSL_MODE_RELEASE_BUFFERS 옵션이 활성화되었을 때 발생 (해당 옵션은 기본적으로 비활성 상태임)    
anonymous ECDH ciphersuites가 활성화된 OpenSSL TLS 클라이언트에 서비스 거부 공격이 발생할 수 있는 취약점 (CVE-2014-3470)       

#### 영향 받는 제품 및 버전
OpenSSL 0.9.8 대 버전   
OpenSSL 1.0.0 대 버전   
OpenSSL 1.0.1 대 버전    
이 중 CVE-2014-0221은 비정상적인 DTLS 핸드셰이크를 OpenSSL DTLS 클라이언트에 전송하여 서비스 거부 공격이 가능한 취약점     
 
## 알아본 CVE-2014-0221

< DTLS 서비스거부 취약점(CVE-2014-0221) >   
o DTLS(Datagram Transport Layer Security)는 TLS를 기반으로 하여암호화된 데이터그램을 전송하게 해주는 프로토콜     
o 비정상적인 DTLS 핸드쉐이크 메시지(DTLS Hello 메시지)를 DTLS클라이언트에 전송할 경우, OpenSSL이 재귀상태에 빠질 수 있도록 구현되어 서비스 거부 공격이 가능     
- DTLS Hello 메시지를 처리하면서 함수 자신을 재귀호출
#### 예시코드 dtls1_get_message_frament method의 재귀호출 부분 예시
```
if(!s->server && s->d1->r_msg_hdr.frag_off == 0 && wire[0] == SSL3_MT_HELLO_REQUEST) {
    if(wire[1] == 0 && wire[2] == 0 && wire[3] == 0) {
        if(s->msg_callback)
            s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE,
                wire, DTLS1_HM_HEADER_LENGTH, s, s->msg_callback_arg);

            s->init_num = 0;
            return dtls1_get_message_fragment(s, st1, stn, max, ok);
    }
    else {
        al=SSL_AD_UNEXPECTED_MESSAGE;
        SSLerr(SSL_F_DTLS1_GET_MESSAGE_FRAGMENT,SSL_R_UNEXPECTED_MESSAGE);
        goto f_err;
    }
}
```


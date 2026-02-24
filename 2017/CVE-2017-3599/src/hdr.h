#pragma once
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <fstream>

#pragma comment (lib, "Ws2_32.lib")
using namespace std;

#pragma pack(1)
struct mysql_login_req {
	uint8_t len;
	uint16_t zero;
	uint8_t num;

	uint16_t ccap;
	uint16_t eccap;
	uint32_t mpack;
	uint8_t cset;
};

SOCKET connect_host(string ip, string port);
void dos(SOCKET sock);

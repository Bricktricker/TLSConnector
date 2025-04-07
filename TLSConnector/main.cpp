#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "tls.h"
#include "CertificateStore.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Bcrypt.lib")

#define URL "google.com"

// https://stackoverflow.com/questions/874134/find-out-if-string-ends-with-another-string-in-c
static bool endsWith(std::string_view str, std::string_view suffix) {
	return str.size() >= suffix.size() && 0 == str.compare(str.size() - suffix.size(), suffix.size(), suffix);
}

int main() {
	CertificateStore certStore;
	try {
		certStore.addCertificates("firefoxCAs.pem");
	}
	catch (const std::exception& e) {
		std::cerr << e.what() << '\n';
		return 1;
	}

	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		std::cerr << "WSAStartup failed with error " << iResult << '\n';
		return 1;
	}
	
	addrinfo hints, *result;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	iResult = getaddrinfo(URL, "443", &hints, &result);
	if (iResult != 0) {
		std::cerr << "getaddrinfo failed with error " << iResult << '\n';
		WSACleanup();
		return 1;
	}

	SOCKET connectedSocket = INVALID_SOCKET;
	for (addrinfo* ptr = result; ptr != NULL; ptr = ptr->ai_next) {

		// Create a SOCKET for connecting to server
		connectedSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (connectedSocket == INVALID_SOCKET) {
			std::cerr << "socket failed with error " << WSAGetLastError() << '\n';
			WSACleanup();
			return 1;
		}

		// Connect to server.
		iResult = connect(connectedSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(connectedSocket);
			connectedSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	try
	{	
		TLSConnector tls(connectedSocket);
		tls.setCertificateStore(&certStore);
		tls.connect(URL);
		std::string req = "GET / HTTP/1.1\r\nHost: ";
		req += URL;
		req += "\r\n\r\n";
		tls.sendEncrypted(req);
		std::string fullData;
		do {
			const auto partData = tls.receiveEncryptedStr();
			std::cout << partData;
			fullData += partData;
		} while (!endsWith(fullData, "\r\n\r\n") && !endsWith(fullData, "\n\n"));
		tls.closeEncryption();
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << '\n';
	}

	closesocket(connectedSocket);
	WSACleanup();

	system("pause");
	return 0;
}
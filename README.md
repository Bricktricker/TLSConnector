# TLSConnector

TLSConnector is a learning project designed to help understand and implement TLS 1.2 for a client using the Windows BCRYPT API. This project is for educational purposes only and should **not** be used in production environments. It missing many features and has a lot of security issues. 

## Supported Features
Ciphers:
 - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
 - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
 - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
 - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA

Certificate signature algorithms:
- ecdsa-with-SHA256
- ecdsa-with-SHA384
- sha256WithRSAEncryption
- sha384WithRSAEncryption
- sha512WithRSAEncryption

## Usage
```C++
#include <tls.h>
#include <CertificateStore.h>

int main() {

	// Load CA root certificates
	CertificateStore certStore;
	certStore.addCertificates("firefoxCAs.pem");

	// open socket to target server
	// ...

	// Establish TLS connection
	TLSConnector tls(connectedSocket);
	tls.setCertificateStore(&certStore);
	tls.connect(URL);
	
	// Send HTTP Request
	std::string req = "GET / HTTP/1.1\r\nHost: ";
	req += URL;
	req += "\r\n\r\n";
	tls.sendEncrypted(req);
	
	// Read response
	std::string fullData;
	do {
		const auto partData = tls.receiveEncryptedStr();
		std::cout << partData;
		fullData += partData;
	} while (!endsWith(fullData, "\r\n\r\n") && !endsWith(fullData, "\n\n"));
	tls.closeEncryption();

	return 0;
}
```

#pragma once
#include <winsock2.h>
#include <Windows.h>
#include <bcrypt.h>
//#include <ntstatus.h> // including this causes some macro redefinition warnings
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <memory>
#include <iterator>

#include "BufferHandler.h"
#include "Crypto.h"
#include "CertificateStore.h"

//hexdump
#include <ctype.h>
#include <stdio.h>
#include <assert.h>

#include <iostream>
/*
https://tls.ulfheim.net/
https://tools.ietf.org/html/rfc5246

*/

class TLSConnector {

	struct Cipher {

		enum AesMode {
			CBC,
			GCM
		};

		Cipher(
			const LPCWSTR _prfHash,
			const size_t _macSize,
			const size_t _aesKeySize,
			const size_t _explicitIvSize,
			const size_t _fixedIvSize,
			const LPCWSTR _hmacAlgo,
			const AesMode _aesMode)
			:	prfHash(_prfHash),
				macSize(_macSize),
				aesKeySize(_aesKeySize),
				explicitIvSize(_explicitIvSize),
				fixedIvSize(_fixedIvSize),
				hmacAlgo(_hmacAlgo),
				aesMode(_aesMode)
		{}
		Cipher(const Cipher&) = default;
		Cipher& operator=(const Cipher&) = default;

		LPCWSTR prfHash;
		size_t macSize;
		size_t aesKeySize;
		size_t explicitIvSize;
		size_t fixedIvSize;
		LPCWSTR hmacAlgo;
		AesMode aesMode;
	};

	struct HandshakeData {
		explicit HandshakeData(const std::string& _host)
			: host(_host), certPublicKey(nullptr)
		{}

		std::vector<byte> clientRandom;
		std::vector<byte> serverRandom;
		std::vector<byte> serverPublickey;
		std::unique_ptr<RUNNING_HASH> handshakeHash;
		const std::string host;
		BCRYPT_KEY_HANDLE certPublicKey;

		const std::array<std::pair<uint16_t, Cipher>, 6> ciphers {{
					//format: PRF_HASH, MAC size, AES key size (bytes), explicit iv size (transmitted in enc packet), fixed iv size (derived from PRF), HMAC algorithm, AES mode
			{0xc030, { BCRYPT_SHA384_ALGORITHM, 0, 32, 8, 4, BCRYPT_SHA256_ALGORITHM, Cipher::AesMode::GCM }},	//TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
			{0xc02f, { BCRYPT_SHA256_ALGORITHM, 0, 16, 8, 4, BCRYPT_SHA256_ALGORITHM, Cipher::AesMode::GCM }}, //TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			{0xc028, { BCRYPT_SHA384_ALGORITHM, 48, 32, 16, 0, BCRYPT_SHA384_ALGORITHM, Cipher::AesMode::CBC }}, //TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
			{0xc027, { BCRYPT_SHA256_ALGORITHM, 32, 16, 16, 0, BCRYPT_SHA256_ALGORITHM, Cipher::AesMode::CBC }}, //TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
			{0xc014, { BCRYPT_SHA256_ALGORITHM, 20, 32, 16, 0, BCRYPT_SHA1_ALGORITHM, Cipher::AesMode::CBC }}, //TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
			{0xc013, { BCRYPT_SHA256_ALGORITHM, 20, 16, 16, 0, BCRYPT_SHA1_ALGORITHM, Cipher::AesMode::CBC }}, //TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
		}};
	};

	struct ConnectionData {
		ConnectionData()
			: cipher(nullptr, 0, 0, 0, 0, nullptr, Cipher::AesMode::CBC), //dummy cipher
			sendKey(nullptr),
			recvKey(nullptr)
		{}

		Cipher cipher;

		BCRYPT_KEY_HANDLE sendKey;
		BCRYPT_KEY_HANDLE recvKey;

		std::vector<byte> clientMac;
		std::vector<byte> serverMac;
		std::vector<byte> clientIV;
		std::vector<byte> serverIV;

		std::vector<byte> masterSecret;

		uint64_t send_seq_num = 0;
		uint64_t recv_seq_num = 0;
		bool serverEncryption = false;
		bool clientEncryption = false;
	};

public:
	explicit TLSConnector(const SOCKET socket) : m_socket(socket) {}
	~TLSConnector() {
		destroyKeys();
	}

	void setCertificateStore(const CertificateStore* certStore) {
		m_certStore = certStore;
	}

	void connect(const std::string& host) {
		HandshakeData handshake(host);

		{
			const auto clientHelloData = getClientHello(&handshake);
			sendRecord(0x16, 0x1, BufferWrapper(clientHelloData));
		}

		receiveAndHandleRecord(&handshake); //server hello
		receiveAndHandleRecord(&handshake); //server certificate

		if (true) { //uses (EC)DHE_ key exchange methods
			receiveAndHandleRecord(&handshake); // sever key exchange
		}
		receiveAndHandleRecord(&handshake); //server hello done

		const std::vector<byte> clientPublicKey = generateMasterSecret(&handshake);
		sendClientKeyExchange(clientPublicKey, &handshake);
		sendChangeCipherSpec();
		sendClientFinish(&handshake);

		receiveAndHandleRecord(&handshake); //server change cipher spec
		receiveAndHandleRecord(&handshake); //server finish
	}

	void sendEncrypted(const std::vector<byte>& data) {
		sendRecord(0x17, 0x3, BufferWrapper(data));
	}

	void sendEncrypted(const std::string_view data) {
		sendRecord(0x17, 0x3, BufferWrapper((byte*)data.data(), data.size()));
	}

	void sendEncrypted(const byte* ptr, const size_t size) {
		sendRecord(0x17, 0x3, BufferWrapper(ptr, size));
	}

	std::vector<byte> receiveEncrypted() {
		const auto data = receiveRecord();
		BufferWrapper wrapper(data);
		BufferReader reader(wrapper);

		const byte type = reader.read();
		const size_t tlsVersion = reader.readU16();
		const size_t recordSize = reader.readU16();

		auto recordVec = reader.readArrayRaw(recordSize);

		if (connectionData.serverEncryption) {
			recordVec = decryptRecord(BufferReader(recordVec), type);
			connectionData.recv_seq_num++;
		}

		// TODO: check for type 0x15, if the server closes the connection (with a close notify)
		if (type != 0x17) {
			// no application data
			throw std::runtime_error("Expected application data");
		}

		return recordVec;
	}

	std::string receiveEncryptedStr() {
		const auto data = receiveEncrypted();
		return std::string(reinterpret_cast<const char*>(data.data()), data.size());
	}

	void closeEncryption() {
		const std::array<byte, 2> recordContent{ 0x01, 0x00 };
		sendRecord(0x15, 0x3, BufferWrapper(recordContent.data(), recordContent.size()));
		destroyKeys();
	}

	void destroyKeys() {
		if (connectionData.sendKey != nullptr) {
			BCryptDestroyKey(connectionData.sendKey);
			connectionData.sendKey = nullptr;
		}
		if (connectionData.recvKey != nullptr) {
			BCryptDestroyKey(connectionData.recvKey);
			connectionData.recvKey = nullptr;
		}
	}

private:
	const SOCKET m_socket;
	ConnectionData connectionData;
	const CertificateStore* m_certStore;

	Cipher getCipher(const HandshakeData* handshake, const uint16_t chiperId) {
		const auto itr = std::find_if(begin(handshake->ciphers), end(handshake->ciphers), [&chiperId](const auto &v) { return v.first == chiperId; });
		if (itr != end(handshake->ciphers)) {
			return itr->second;
		}
		else {
			throw std::runtime_error("unsupported cipher");
		}
	}

	// Sends the client hello message https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.2
	std::vector<byte> getClientHello(HandshakeData* handshake) {
		BufferBuilder buf;

		buf.putArray({3, 3}); //TLS 1.2 Client version

		if (handshake->clientRandom.empty()) {
			handshake->clientRandom = getRandomData(32);
		}
		buf.putArray(handshake->clientRandom);

		buf.put(0); //session id (no session)

		buf.putU16(handshake->ciphers.size() * sizeof(uint16_t));
		for (const auto& c : handshake->ciphers) {
			buf.putU16(c.first);
		}

		//copmpression methods (No compression)
		buf.putArray({1, 0});

		//extensions
		{
			BufferBuilder extBuf;

			{
				//SNI extension https://datatracker.ietf.org/doc/html/rfc6066#page-6
				extBuf.putArray({ 0, 0 }); //extension 'server name'
				extBuf.putU16(handshake->host.size() + 5);
				extBuf.putU16(handshake->host.size() + 3); //only entry length

				extBuf.put(0); //list entry type 'DNS hostname'

				//size + host name string
				extBuf.putU16(handshake->host.size());
				extBuf.putArray((byte*)handshake->host.data(), handshake->host.size());
			}

			{
				//signature algorithms extension https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.4.1
				extBuf.putArray({ 0x00, 0x0d }); //extension 'Signature Algorithms'
				const byte signatureAlgos[] = {
					0x04, 0x01, // RSA/PKCS1/SHA256
					0x05, 0x01, // RSA/PKCS1/SHA384
					0x06, 0x01 // RSA/PKCS1/SHA512
				};
				//length information
				size_t signatureAlgLength = sizeof(signatureAlgos);
				extBuf.putU16(signatureAlgLength + 2);
				extBuf.putU16(signatureAlgLength);

				extBuf.putArray(signatureAlgos, signatureAlgLength);
			}

			{
				//Renegotiation Info extension
				extBuf.putArray({
						0xff, 0x01, //Renegotiation Info
						0x00, 0x01, //1 bytes is following
						0x00 //length is zero
					});
			}

			//Supported groups extension (hardcoded to only suport x25519 curve)
			extBuf.putArray({0x00, 0x0a}); // extension 'supported groups'
			extBuf.putU16(4);
			extBuf.putU16(2);
			extBuf.putArray({0x00, 0x1d}); // curve x25519

			//EC points formats extension
			extBuf.putArray({ 0x00, 0x0b }); //extension 'EC points format'
			extBuf.putU16(2);
			extBuf.put(1);
			extBuf.put(0); // uncompressed form

			buf.putU16(extBuf.size());
			buf.putArray(extBuf.data());
		}

		BufferBuilder handshakeBuf(buf.size() + 4);
		handshakeBuf.put(1); //handshake message type
		handshakeBuf.putU24(buf.size());
		handshakeBuf.putArray(buf.data());

		return handshakeBuf.data();
	}

	// receives and parses the Server Hello message https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.3
	void receiveServerHello(HandshakeData* handshake, BufferReader helloBuffer, const size_t tlsVersion) {
		if (tlsVersion != 0x0303) {
			throw std::runtime_error("unexpected tls version");
		}

		if (helloBuffer.readU16() != 0x0303) {
			throw std::runtime_error("unexpected tls version");
		}

		handshake->serverRandom = helloBuffer.readArrayRaw(32);
		const size_t sessionIdLength = helloBuffer.read();
		if (sessionIdLength > 0) {
			helloBuffer.skip(sessionIdLength); //ignore session id
		}
		const uint16_t cipherId = static_cast<uint16_t>(helloBuffer.readU16());
		std::cout << "cipher: " << ((cipherId & 0xff00) >> 8) << ' ' << (cipherId & 0xff) << '\n';
		connectionData.cipher = getCipher(handshake, cipherId);
		if (helloBuffer.read() != 0) {
			throw std::runtime_error("unexpected compression method");
		}
		if (helloBuffer.remaining() > 0) {
			const size_t extensionLength = helloBuffer.readU16();
			std::cout << extensionLength << " bytes of extension data\n";
		}

		handshake->handshakeHash = std::make_unique<RUNNING_HASH>(connectionData.cipher.prfHash);

		//insert client hello and server hello into hash, need to recreate handshake header for hash
		handshake->handshakeHash->addData(getClientHello(handshake));
		BufferBuilder helloBuilder;
		helloBuilder.put(0x02); //server hello record
		helloBuilder.putU24(helloBuffer.bufferSize());

		handshake->handshakeHash->addData(helloBuilder.data());
		handshake->handshakeHash->addData(helloBuffer.data(), helloBuffer.bufferSize());
	}
	
	// receives the server certificate https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.2 
	void receiveCertificate(HandshakeData* handshake, BufferReader handshakeBuffer, const size_t tlsVersion) {
		if (tlsVersion != 0x0303) {
			throw std::runtime_error("unexpected tls version");
		}
		const size_t certificatesLength = handshakeBuffer.readU24();
		size_t bytesHandled = 0;
		std::vector<Certificate> sendCerts;

		while (bytesHandled < certificatesLength) {
			const size_t certLength = handshakeBuffer.readU24();
			bytesHandled += 3;

			CertReader certReader(handshakeBuffer);
			sendCerts.push_back(certReader.getCertificate());

			bytesHandled += certLength;
		}

		// Validate the certificates if we have a certificate store
		const bool isValid = m_certStore == nullptr || m_certStore->validateCertChain(sendCerts, handshake->host);
			
		if (!isValid) {
			std::for_each(sendCerts.begin(), sendCerts.end(), [](const Certificate& cert) {
				const auto status = BCryptDestroyKey(cert.publicKey);
				assert(status == 0);
			});
			throw std::runtime_error("Could not validate certificate");
		}

		if (!sendCerts.empty() && m_certStore != nullptr) {
			handshake->certPublicKey = sendCerts.front().publicKey;
			std::for_each(std::next(sendCerts.begin()), sendCerts.end(), [](const Certificate& cert) {
				const auto status = BCryptDestroyKey(cert.publicKey);
				assert(status == 0);
			});
		}

	}

	// receives the data for the key exchange https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.3
	void receiveKeyExchange(HandshakeData* handshake, BufferReader keyInfoBuffer, const size_t tlsVersion) {
		if (tlsVersion != 0x0303) {
			throw std::runtime_error("unexpected tls version");
		}

		const size_t curveType = keyInfoBuffer.read();
		if (curveType != 3) { //only support 'named_curve'
			throw std::runtime_error("unsupported curve type");
		}
		const size_t curve = keyInfoBuffer.readU16();
		if (curve != 0x001d) { //only suport x25519 curve
			throw std::runtime_error("unsupported curve");
		}

		const size_t publicKeyLength = keyInfoBuffer.read();
		handshake->serverPublickey = keyInfoBuffer.readArrayRaw(publicKeyLength);

		//signature, not checked in this implementation
		const uint8_t hashAlgorithm = keyInfoBuffer.read(); // https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.4.1
		const uint8_t signatureAlgorithm = keyInfoBuffer.read();
		const size_t signatureLength = keyInfoBuffer.readU16();
		std::vector<byte> signature = keyInfoBuffer.readArrayRaw(signatureLength);
		assert(keyInfoBuffer.remaining() == 0);

		if (signatureAlgorithm != 1/*RSA*/) {
			throw std::runtime_error("Unexpected signature algorithm, expected RSA");
		}

		LPCWSTR hashAlgName = nullptr;
		switch (hashAlgorithm) {
		case 2: hashAlgName = BCRYPT_SHA1_ALGORITHM; break;
		case 4: hashAlgName = BCRYPT_SHA256_ALGORITHM; break;
		case 5: hashAlgName = BCRYPT_SHA384_ALGORITHM; break;
		case 6: hashAlgName = BCRYPT_SHA512_ALGORITHM; break;
		default: throw std::runtime_error("Unsupported hash algorithm");
		}

		if (handshake->certPublicKey) {
			BCRYPT_PKCS1_PADDING_INFO paddingInfo = {};
			paddingInfo.pszAlgId = hashAlgName;

			RUNNING_HASH hashObj(hashAlgName);
			hashObj.addData(handshake->clientRandom);
			hashObj.addData(handshake->serverRandom);
			hashObj.addData({ 3, 0, 0x1d, static_cast<byte>(handshake->serverPublickey.size()) }); // Curve info from above, is hardcoded to one
			hashObj.addData(handshake->serverPublickey);
			std::vector<byte> hashBytes = hashObj.finish();

			NTSTATUS status = BCryptVerifySignature(handshake->certPublicKey, &paddingInfo,
				hashBytes.data(), hashBytes.size(),
				signature.data(), signature.size(), BCRYPT_PAD_PKCS1);

			if (status != 0) {
				// signature not valid
				throw std::runtime_error("Server public key signature not valid");
			}

			status = BCryptDestroyKey(handshake->certPublicKey);
			handshake->certPublicKey = nullptr;
			assert(status == 0);
		}
	}

	// receives the Server Hello Done message https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.5
	void receiveHelloDone(HandshakeData* handshake, BufferReader handshakeBuffer, const size_t tlsVersion) {
		if (tlsVersion != 0x0303) {
			throw std::runtime_error("unexpected tls version");
		}
		if(handshakeBuffer.bufferSize() != 0) {
			throw std::runtime_error("unexpected data in Server Hello Done");
		}
	}

	std::vector<byte> prf(const std::string_view label, const BufferWrapper seed, const size_t outputLength, const std::vector<byte>& masterSecret) {
		const BufferWrapper labelBuf((byte*)label.data(), label.size());
		
		HMAC hmac(connectionData.cipher.prfHash);
		hmac.setSecret(masterSecret);

		std::vector<byte> outBuffer;

		auto A_buffer = hmac.getHash(labelBuf, seed); //a1
		while (outBuffer.size() < outputLength) {
			const auto tmpBuffer = hmac.getHash(BufferWrapper(A_buffer), labelBuf, seed); //p1
			outBuffer.insert(end(outBuffer), begin(tmpBuffer), begin(tmpBuffer) + min(tmpBuffer.size(), outputLength - outBuffer.size()));
			A_buffer = hmac.getHash(BufferWrapper(A_buffer));
		}

		return outBuffer;
	}

	//generates a x25519 curve private/public key pair, generates the master secret and needed keys, returns the raw bytes for the client public key
	std::vector<byte> generateMasterSecret(HandshakeData* handshake) {
		BCRYPT_ALG_HANDLE hAlg = nullptr;
		NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_ALGORITHM, NULL, 0);
		if (status != 0) {
			throw std::runtime_error("Could not open curve x25519 provider");
		}

		status = BCryptSetProperty(hAlg, BCRYPT_ECC_CURVE_NAME, (PUCHAR)BCRYPT_ECC_CURVE_25519, sizeof(BCRYPT_ECC_CURVE_25519), 0);
		if (status != 0) {
			throw std::runtime_error("Could not set curve parameter");
		}

		BCRYPT_KEY_HANDLE clientKeyHandle = nullptr;
		status = BCryptGenerateKeyPair(hAlg, &clientKeyHandle, 255, 0);
		if (status != 0) {
			throw std::runtime_error("Could not generate key pair");
		}

		status = BCryptFinalizeKeyPair(clientKeyHandle, 0);
		if (status != 0) {
			throw std::runtime_error("Could not finalize key pair");
		}

		ULONG pcbResult = 0;
		status = BCryptExportKey(clientKeyHandle, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &pcbResult, 0);
		if (status != 0) {
			throw std::runtime_error("Could not export public key");
		}

		std::vector<byte> publicKey(pcbResult, 0); //client public key

		status = BCryptExportKey(clientKeyHandle, 0, BCRYPT_ECCPUBLIC_BLOB, publicKey.data(), static_cast<ULONG>(publicKey.size()), &pcbResult, 0);
		if (status != 0) {
			throw std::runtime_error("Could not export public key");
		}

		//store raw public key from client in rawPublicKey
		BufferReader tmpReader(publicKey);
		tmpReader.skip(4); //dwMagic
		const size_t cbKey = htonl(static_cast<u_long>(tmpReader.readU32()));
		const std::vector<byte> rawPublicKey = tmpReader.readArrayRaw(cbKey);

		//import server public key
		BCRYPT_KEY_HANDLE serverKeyHandle = nullptr;
		{
			BufferBuilder publicKeyBuf;
			publicKeyBuf.putU32(htonl(BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC));
			publicKeyBuf.putU32(htonl(static_cast<u_long>(handshake->serverPublickey.size())));
			publicKeyBuf.putArray(handshake->serverPublickey);

			//expand buffer with zeros to a size of 0x48 bytes.
			std::vector<byte> tmp(0x48 - publicKeyBuf.size(), 0);
			publicKeyBuf.putArray(tmp);

			status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &serverKeyHandle, (PUCHAR)publicKeyBuf.data().data(), static_cast<ULONG>(publicKeyBuf.size()), 0);
			if (status != 0) {
				throw std::runtime_error("Could not import server public key");
			}
		}

		//generate pre master secret
		BCRYPT_SECRET_HANDLE preMasterSecret = nullptr;
		status = BCryptSecretAgreement(clientKeyHandle, serverKeyHandle, &preMasterSecret, 0);
		if (status != 0) {
			throw std::runtime_error("Could not generate pre master secret");
		}

		// generate master secret
		std::array<BCryptBuffer, 4> keyGenDescData;

		keyGenDescData[0].BufferType = KDF_TLS_PRF_LABEL;
		const std::string_view masterSecretStr("master secret");
		keyGenDescData[0].cbBuffer = static_cast<ULONG>(masterSecretStr.size()); // 'master secret' length
		keyGenDescData[0].pvBuffer = (PVOID)masterSecretStr.data();

		std::vector<byte> seed;
		seed.insert(end(seed), begin(handshake->clientRandom), end(handshake->clientRandom));
		seed.insert(end(seed), begin(handshake->serverRandom), end(handshake->serverRandom));
		assert(seed.size() == 64);
		keyGenDescData[1].BufferType = KDF_TLS_PRF_SEED;
		keyGenDescData[1].cbBuffer = static_cast<ULONG>(seed.size());
		keyGenDescData[1].pvBuffer = seed.data();

		DWORD protocolVersion = 0x0303; // TLS1_2_PROTOCOL_VERSION
		keyGenDescData[2].BufferType = KDF_TLS_PRF_PROTOCOL;
		keyGenDescData[2].cbBuffer = sizeof(DWORD);
		keyGenDescData[2].pvBuffer = &protocolVersion;

		keyGenDescData[3].BufferType = KDF_HASH_ALGORITHM;
		keyGenDescData[3].cbBuffer = static_cast<ULONG>(wcslen(connectionData.cipher.prfHash) * sizeof(WCHAR) + 2 + 1); // Length of 'SHA256' / 'SHA384'
		keyGenDescData[3].pvBuffer = (PVOID)connectionData.cipher.prfHash;

		BCryptBufferDesc keyGenDesc;
		keyGenDesc.ulVersion = BCRYPTBUFFER_VERSION;
		keyGenDesc.cBuffers = static_cast<ULONG>(keyGenDescData.size()); //Number of keyGenDescData elements
		keyGenDesc.pBuffers = keyGenDescData.data();

		ULONG bufferSize = 0;
		status = BCryptDeriveKey(preMasterSecret, BCRYPT_KDF_TLS_PRF, &keyGenDesc, nullptr, 0, &bufferSize, 0);
		if (status != 0) {
			throw std::runtime_error("Could not generate master secret");
		}

		assert(bufferSize == 0x30);
		connectionData.masterSecret.resize(bufferSize, 0);
		status = BCryptDeriveKey(preMasterSecret, BCRYPT_KDF_TLS_PRF, &keyGenDesc, connectionData.masterSecret.data(), static_cast<ULONG>(connectionData.masterSecret.size()), &bufferSize, 0);
		if (status != 0) {
			throw std::runtime_error("Could not generate master secret");
		}

		status = BCryptDestroySecret(preMasterSecret);
		preMasterSecret = NULL;
		if (status != 0) {
			throw std::runtime_error("Could not delete pre master secret");
		}
		
		//https://github.com/NetworkState/cwitch/blob/55f8fabcf6cdf2f3afe9e9f26dcd8bd0e30a5db0/tls12.h#L88
		//key expansion to generate macs and write keys
		{
			BufferBuilder seedPRF(64);
			seedPRF.putArray(handshake->serverRandom);
			seedPRF.putArray(handshake->clientRandom);

			const size_t macKeySize = connectionData.cipher.macSize; //mac key, 2x 20 bytes for SHA1 and 2x 32 bytes for SHA256. 0 for AES GCM mode!?
			const size_t encKeySize = connectionData.cipher.aesKeySize; //enc_key_length, 2x 16 bytes for AES 128 and 2x 32 bytes for AES 256
			const size_t fixedIvLength = connectionData.cipher.fixedIvSize; //fixed_iv_length, 2x 4bytes for AES-GCM
			const size_t expansionSize = 2 * macKeySize + 2 * encKeySize + 2 * fixedIvLength;
			const auto keyExpansion = prf("key expansion", seedPRF.wrapper(), expansionSize, connectionData.masterSecret);
			BufferReader reader(keyExpansion);

			if (macKeySize > 0) {
				connectionData.clientMac = reader.readArrayRaw(macKeySize);
				connectionData.serverMac = reader.readArrayRaw(macKeySize);
			}
			if (encKeySize > 0) {
				BCRYPT_ALG_HANDLE aesAlgorithm;
				status = BCryptOpenAlgorithmProvider(&aesAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
				if (status != 0) {
					throw std::runtime_error("could not open AES algorithm");
				}
				const PUCHAR aesMode = (PUCHAR)(connectionData.cipher.aesMode == Cipher::AesMode::CBC ? BCRYPT_CHAIN_MODE_CBC : BCRYPT_CHAIN_MODE_GCM);
				static_assert(sizeof(BCRYPT_CHAIN_MODE_CBC) == sizeof(BCRYPT_CHAIN_MODE_GCM), "Aes chain mode string size differ");
				status = BCryptSetProperty(aesAlgorithm, BCRYPT_CHAINING_MODE, aesMode, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
				if (status != 0) {
					throw std::runtime_error("could not set caining mode");
				}

				if (connectionData.cipher.aesMode == Cipher::AesMode::GCM) {
					BCRYPT_AUTH_TAG_LENGTHS_STRUCT tagLength;
					ULONG bytesCopied;
					status = BCryptGetProperty(aesAlgorithm, BCRYPT_AUTH_TAG_LENGTH, (PUCHAR)& tagLength, sizeof(tagLength), &bytesCopied, 0);

					assert(tagLength.dwMaxLength == 16);
				}

				{
					const auto keyData = reader.readArrayRaw(encKeySize);
					status = BCryptGenerateSymmetricKey(aesAlgorithm, &connectionData.sendKey, NULL, 0, (PUCHAR)keyData.data(), static_cast<ULONG>(keyData.size()), 0);
					if (status != 0) {
						throw std::runtime_error("could not import AES key");
					}
				}

				{
					const auto keyData = reader.readArrayRaw(encKeySize);
					status = BCryptGenerateSymmetricKey(aesAlgorithm, &connectionData.recvKey, NULL, 0, (PUCHAR)keyData.data(), static_cast<ULONG>(keyData.size()), 0);
					if (status != 0) {
						throw std::runtime_error("could not import AES key");
					}
				}
			}
			if (fixedIvLength > 0) {
				connectionData.clientIV = reader.readArrayRaw(fixedIvLength);
				connectionData.serverIV = reader.readArrayRaw(fixedIvLength);
			}

		}

		closeAlgorithm(hAlg);

		return rawPublicKey;
	}

	std::vector<byte> encrypt(const BufferWrapper& data, const byte messageType) const {
		const size_t iv_size = connectionData.cipher.explicitIvSize;
		auto iv = getRandomData(iv_size); // gets modified during encryption

		BufferBuilder outBuf;
		outBuf.putArray(iv);
		if (connectionData.cipher.aesMode == Cipher::AesMode::CBC) {

			BufferBuilder encryptContent;
			encryptContent.putArray(data);

			//MAC
			{
				BufferBuilder macInput;
				macInput.putU64(connectionData.send_seq_num);
				macInput.put(messageType); //message type
				macInput.putArray({ 3, 3 }); //version, TLS 1.2
				macInput.putU16(data.size());

				HMAC hmac(connectionData.cipher.hmacAlgo);
				hmac.setSecret(connectionData.clientMac);
				const std::vector<byte> hash = hmac.getHash(macInput.wrapper(), data);
				encryptContent.putArray(hash);
			}

			//Padding
			{
				const size_t multipleBlockLength = (((encryptContent.size() + 1) + iv.size() - 1) / iv.size()) * iv.size(); //add 1 to encryptContent for the byte containing the padding length
				assert(multipleBlockLength > encryptContent.size());
				const byte paddingLength = static_cast<byte>(multipleBlockLength - encryptContent.size() - 1);
				encryptContent.putArray(std::vector<byte>(paddingLength, paddingLength));
				encryptContent.put(paddingLength);
			}

			//https://tools.ietf.org/html/rfc5246#section-6.2.3.2
			//https://crypto.stackexchange.com/questions/50815/clarification-needed-in-tls-1-2-key-derivation-process
			//https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt

			ULONG outSize = 0;
			NTSTATUS status = BCryptEncrypt(connectionData.sendKey, (PUCHAR)encryptContent.data().data(), static_cast<ULONG>(encryptContent.size()), NULL, (PUCHAR)iv.data(), static_cast<ULONG>(iv.size()), NULL, 0, &outSize, 0);
			if (status != 0) {
				std::runtime_error("could not encrypt data");
			}

			PUCHAR encStart = outBuf.reserve(outSize);
			status = BCryptEncrypt(connectionData.sendKey, (PUCHAR)encryptContent.data().data(), static_cast<ULONG>(encryptContent.size()), NULL, (PUCHAR)iv.data(), static_cast<ULONG>(iv.size()), encStart, outSize, &outSize, 0);
			if (status != 0) {
				std::runtime_error("could not encrypt data");
			}
		}
		else if (connectionData.cipher.aesMode == Cipher::AesMode::GCM) {
			
			BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aead;
			BCRYPT_INIT_AUTH_MODE_INFO(aead);

			BufferBuilder nonce;
			nonce.putArray(connectionData.clientIV);
			nonce.putArray(iv);

			aead.pbNonce = nonce.data().data();
			aead.cbNonce = static_cast<ULONG>(nonce.size()); // should be 12
			assert(aead.cbNonce == 12);

			BufferBuilder additionalData;
			additionalData.putU64(connectionData.send_seq_num);
			additionalData.put(messageType); //message type
			additionalData.putArray({ 3, 3 }); //version, TLS 1.2
			additionalData.putU16(data.size());

			aead.pbAuthData = additionalData.data().data();
			aead.cbAuthData = static_cast<ULONG>(additionalData.size());

			ULONG outSize = 0;
			NTSTATUS status = BCryptEncrypt(connectionData.sendKey, (PUCHAR)data.data(), static_cast<ULONG>(data.size()), &aead, NULL, 0, NULL, 0, &outSize, 0);
			if (status != 0) {
				std::runtime_error("could not encrypt data");
			}

			constexpr size_t tagLength = 16;
			PUCHAR encStart = outBuf.reserve(outSize + tagLength);
			aead.pbTag = encStart + outSize;
			aead.cbTag = tagLength;

			status = BCryptEncrypt(connectionData.sendKey, (PUCHAR)data.data(), static_cast<ULONG>(data.size()), &aead, NULL, 0, encStart, outSize, &outSize, 0);
			if (status != 0) {
				std::runtime_error("could not encrypt data");
			}

		}else {
			std::runtime_error("Invalid aes cipher mode");
		}

		return outBuf.data();
	}

	std::vector<byte> decryptRecord(BufferReader record, const uint8_t recordType) {
		const std::vector<byte> iv = record.readArrayRaw(connectionData.cipher.explicitIvSize);

		if (connectionData.cipher.aesMode == Cipher::AesMode::CBC) {
			ULONG outSize = 0;
			NTSTATUS status = BCryptDecrypt(connectionData.recvKey, (PUCHAR)record.posPtr(), static_cast<ULONG>(record.bufferSize() - iv.size()), NULL, (PUCHAR)iv.data(), static_cast<ULONG>(iv.size()), NULL, 0, &outSize, 0);
			if (status != 0) {
				std::runtime_error("could not decrypt data");
			}
			std::vector<byte> outBuf(outSize, 0);
			status = BCryptDecrypt(connectionData.recvKey, (PUCHAR)record.posPtr(), static_cast<ULONG>(record.bufferSize() - iv.size()), NULL, (PUCHAR)iv.data(), static_cast<ULONG>(iv.size()), outBuf.data(), static_cast<ULONG>(outBuf.size()), &outSize, 0);
			if (status != 0) {
				std::runtime_error("could not decrypt data");
			}

			//remove padding
			const auto paddingLength = outBuf.back();
			outBuf.resize(outBuf.size() - (paddingLength + 1));

			const size_t macSize = connectionData.cipher.macSize;
			const size_t payloadSize = outBuf.size() - macSize;
			const std::vector<byte> payload(outBuf.begin(), outBuf.begin() + payloadSize);

			//MAC
			{
				const auto macItr = outBuf.end() - macSize;

				//CHECK MAC
				HMAC hmac(connectionData.cipher.hmacAlgo);
				hmac.setSecret(connectionData.serverMac);

				BufferBuilder macInput;
				macInput.putU64(connectionData.recv_seq_num);
				macInput.put(recordType); //message type
				macInput.putArray({ 3, 3 }); //version, TLS 1.2
				macInput.putU16(payloadSize);

				const auto computedMac = hmac.getHash(macInput.wrapper(), BufferWrapper(payload));
				if (!std::equal(computedMac.begin(), computedMac.end(), macItr)) {
					throw std::runtime_error("Received MAC is corrupted");
				}
			}

			return payload;
		}
		else if(connectionData.cipher.aesMode == Cipher::AesMode::GCM) {

			BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aead;
			BCRYPT_INIT_AUTH_MODE_INFO(aead);

			BufferBuilder nonce;
			nonce.putArray(connectionData.serverIV);
			nonce.putArray(iv);

			aead.pbNonce = nonce.data().data();
			aead.cbNonce = static_cast<ULONG>(nonce.size()); // should be 12
			assert(aead.cbNonce == 12);

			const size_t payloadSize = record.remaining() - 16;
			BufferBuilder additionalData;
			additionalData.putU64(connectionData.recv_seq_num);
			additionalData.put(recordType); //message type
			additionalData.putArray({ 3, 3 }); //version, TLS 1.2
			additionalData.putU16(payloadSize);

			aead.pbAuthData = additionalData.data().data();
			aead.cbAuthData = static_cast<ULONG>(additionalData.size());

			PUCHAR encBegin = (PUCHAR) record.posPtr();
			record.skip(payloadSize);
			aead.pbTag = (PUCHAR) record.posPtr();
			aead.cbTag = 16;
			assert(record.remaining() == aead.cbTag);

			ULONG outSize = 0;
			NTSTATUS status = BCryptDecrypt(connectionData.recvKey, encBegin, static_cast<ULONG>(payloadSize), &aead, NULL, 0, NULL, 0, &outSize, 0);
			if (status != 0) {
				std::runtime_error("could not decrypt data");
			}

			std::vector<byte> outBuf(outSize, 0);
			status = BCryptDecrypt(connectionData.recvKey, encBegin, static_cast<ULONG>(payloadSize), &aead, NULL, 0, outBuf.data(), outSize, &outSize, 0);
			if (status == ((NTSTATUS)0xC000A002L)) { // STATUS_AUTH_TAG_MISMATCH
				throw std::runtime_error("Received MAC is corrupted");
			}else if (status != 0) {
				std::runtime_error("could not decrypt data");
			}

			return outBuf;

		}else {
			throw std::runtime_error("Invalid aes cipher mode");
		}
	}

	void sendClientKeyExchange(const std::vector<byte>& publicKey, HandshakeData* handshake) {
		BufferBuilder handshakeBuf;
		handshakeBuf.put(0x10); //handshake message type 'client key exchange'
		handshakeBuf.putU24(1 + publicKey.size()); //1 + n bytes of public key data follows

		handshakeBuf.put(static_cast<byte>(publicKey.size())); //key length
		handshakeBuf.putArray(publicKey);

		handshake->handshakeHash->addData(handshakeBuf.data());

		sendRecord(0x16, 0x3, handshakeBuf.wrapper());
	}

	void sendChangeCipherSpec() {
		const byte payload = 1;
		sendRecord(0x14, 0x3, BufferWrapper(&payload, 1)); //0x14 = type ChangeCipherSpec record
		connectionData.clientEncryption = true;
	}

	void sendClientFinish(HandshakeData* handshake) {
		BufferBuilder verifyBuilder;
		verifyBuilder.put(0x14); //finish message
		RUNNING_HASH handshakeHashCopy(*handshake->handshakeHash); //copy hash object, so we can get the current hash and can continue to use the old hashobject and add the clientFinish message to it
		const auto handshakeHash = handshakeHashCopy.finish();
		const size_t verifyLength = 12;
		const auto verifyData = prf("client finished", BufferWrapper(handshakeHash), verifyLength, connectionData.masterSecret);
		verifyBuilder.putU24(verifyLength);
		verifyBuilder.putArray(verifyData);

		handshake->handshakeHash->addData(verifyBuilder.data());

		sendRecord(0x16, 0x3, verifyBuilder.wrapper()); //handshake record type
	}

	void receiveChangeCipherSpec(BufferReader payload, const size_t tlsVersion) {
		if (tlsVersion != 0x0303) {
			throw std::runtime_error("unexpected tls version");
		}
		if (payload.bufferSize() != 1 || payload.read() != 0x1) {
			throw std::runtime_error("wrong server change cipherSpec payload");
		}
		connectionData.serverEncryption = true;
	}

	void receiveServerFinish(HandshakeData* handshake, BufferReader verifyData, const size_t tlsVersion) {
		if (tlsVersion != 0x0303) {
			throw std::runtime_error("unexpected record type");
		}

		//compute verify data
		const auto handshakeHash = handshake->handshakeHash->finish();
		handshake->handshakeHash.reset(nullptr);
		const auto computedVerify = prf("server finished", BufferWrapper(handshakeHash), verifyData.bufferSize(), connectionData.masterSecret);

		if (!std::equal(computedVerify.begin(), computedVerify.end(), verifyData.data())) {
			throw std::runtime_error("verify data corrupted");
		}

	}

	void sendRecord(const byte type, const byte subVersion, const BufferWrapper data) {		
		BufferBuilder buf(5);
		buf.put(type);
		buf.putArray({3, subVersion }); //TLS version 1.subVersion

		if (connectionData.clientEncryption) {
			BufferBuilder encBuf;
			const auto encryptedData = encrypt(data, type);
			encBuf.putArray(encryptedData);

			buf.putU16(encBuf.size());

			{ //hexdump send data
				std::vector<byte> tmp;
				tmp.insert(end(tmp), begin(buf.data()), end(buf.data()));
				tmp.insert(end(tmp), begin(encBuf.data()), end(encBuf.data()));
				hexdump(tmp.data(), tmp.size());
			}

			sendData(buf.wrapper());
			sendData(encBuf.wrapper());

			connectionData.send_seq_num++;
		}
		else {
			buf.putU16(data.size());
			{ //hexdump send data
				std::vector<byte> tmp;
				tmp.insert(end(tmp), begin(buf.data()), end(buf.data()));
				tmp.insert(end(tmp), data.data(), data.data() + data.size());
				hexdump(tmp.data(), tmp.size());
			}

			sendData(buf.wrapper());
			sendData(data);
		}
	}

	void sendData(const BufferWrapper data) const {
		size_t bytesSend = 0;
		do {
			int result = send(m_socket, (char*)data.data() + bytesSend, static_cast<int>(data.size() - bytesSend), 0);
			if (result < 0) {
				std::cerr << "Error sending data: " << WSAGetLastError() << '\n';
				throw std::runtime_error("error sending data");
			}
			bytesSend += result;
		} while (bytesSend < data.size());
	}

	void receiveAndHandleRecord(HandshakeData* handshake) {
		const auto data = receiveRecord();
		BufferWrapper wrapper(data);
		BufferReader reader(wrapper);

		const byte type = reader.read();
		const size_t tlsVersion = reader.readU16();
		const size_t recordSize = reader.readU16();

		auto recordVec = reader.readArrayRaw(recordSize);

		if (connectionData.serverEncryption) {
			recordVec = decryptRecord(BufferReader(recordVec), type);
			connectionData.recv_seq_num++;
		}
		handleRecordInternal(BufferWrapper(recordVec), handshake, type, tlsVersion);
	}

	[[nodiscard]] std::vector<byte> receiveRecord() const {
		byte header[5]{ 0 };
		size_t bytesReceived = 0;
		do {
			int headerStatus = recv(m_socket, (char*)header, 5, 0);
			if (headerStatus == 0) {
				throw std::runtime_error("Connection closed");
			}
			else if (headerStatus < 0) {
				throw std::runtime_error("recv failed, check 'WSAGetLastError()'");
			}
			else {
				bytesReceived += headerStatus;
			}
		} while (bytesReceived < 5);

		const size_t msgLength = (static_cast<size_t>(header[3]) << 8) | header[4];
		std::vector<byte> msgContent(msgLength, 0);
		bytesReceived = 0;
		do {
			int status = recv(m_socket, (char*)msgContent.data() + bytesReceived, static_cast<int>(msgLength - bytesReceived), 0);
			if (status == 0) {
				throw std::runtime_error("Connection closed");
			}
			else if (status < 0) {
				throw std::runtime_error("recv failed, check 'WSAGetLastError()'");
			}
			else {
				bytesReceived += status;
			}
		} while (bytesReceived < msgLength);

		msgContent.insert(begin(msgContent), header, header + 5); //prepend message header
		hexdump(msgContent.data(), msgContent.size());

		return msgContent;
	}

	void handleRecordInternal(BufferWrapper wrapper, HandshakeData* handshake, const byte type, const size_t tlsVersion) {
		BufferReader recordReader(wrapper);

		if (type == 0x16) { //handshake message
			if (handshake->handshakeHash && !connectionData.serverEncryption) {
				handshake->handshakeHash->addData(recordReader.data(), recordReader.bufferSize());
			}
			const size_t handshakeType = recordReader.read();
			const size_t handshakeSize = recordReader.readU24();
			BufferReader handshakeData = recordReader.readArray(handshakeSize);

			switch (handshakeType)
			{
			case 0x02: receiveServerHello(handshake, handshakeData, tlsVersion); break;
			case 0x0b: receiveCertificate(handshake, handshakeData, tlsVersion); break;
			case 0x0c: receiveKeyExchange(handshake, handshakeData, tlsVersion); break;
			case 0x0e: receiveHelloDone(handshake, handshakeData, tlsVersion); break;
			case 0x14: receiveServerFinish(handshake, handshakeData, tlsVersion); break;
			default:
				throw std::runtime_error("received unsuported handshake type");
			}
		}
		else if (type == 0x14) {
			receiveChangeCipherSpec(recordReader, tlsVersion);
		}
		else if (type == 0x15) { //alert
			const size_t level = recordReader.read();
			const size_t desc = recordReader.read();
			std::cerr << "Alert: level " << level << ", description: " << desc << '\n';
			throw std::runtime_error("received alert message");
		}
		else {
			throw std::runtime_error("received unsuported record type");
		}
	}

	std::vector<byte> getRandomData(const size_t length) const {
		std::vector<byte> buf(length, 0);

		BCRYPT_ALG_HANDLE hAlg = nullptr;
		NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
		if(status < 0) {
			throw std::runtime_error("Could not open random provider");
		}

		status = BCryptGenRandom(hAlg, buf.data(), static_cast<ULONG>(length), 0);
		if (status != 0) {
			closeAlgorithm(hAlg);
			throw std::runtime_error("Could not generate random data");
		}

		closeAlgorithm(hAlg);

		return buf;
	}

	void closeAlgorithm(BCRYPT_ALG_HANDLE hAlg) const {
		NTSTATUS status = BCryptCloseAlgorithmProvider(hAlg, 0);
		if (status != 0) {
			throw std::runtime_error("Could not close random provider");
		}
	}

	void hexdump(const void *ptr, const size_t buflen) const {
		unsigned char *buf = (unsigned char*)ptr;
		size_t i, j;
		for (i = 0; i < buflen; i += 16) {
			printf("%06x: ", i);
			for (j = 0; j < 16; j++)
				if (i + j < buflen)
					printf("%02x ", buf[i + j]);
				else
					printf("   ");
			printf(" ");
			for (j = 0; j < 16; j++)
				if (i + j < buflen)
					printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
			printf("\n");
		}
	}

};
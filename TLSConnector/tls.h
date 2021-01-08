#pragma once
#include <winsock2.h>
#include <Windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <array>
#include <memory>

#include "BufferHandler.h"
#include "Crypto.h"

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

	struct HandshakeData {
		std::vector<byte> clientRandom;
		std::vector<byte> serverRandom;

		std::vector<byte> serverPublicKey;
		std::unique_ptr<RUNNING_HASH> handshakeHash;
	};

public:
	explicit TLSConnector(const SOCKET socket) : m_socket(socket) {}
	~TLSConnector() = default;

	void connect(const std::string& host) {
		sendClientHello(host);
		receiveServerHello();
		receiveCertificate();
		if (((connectionData.cipher & 0xff00) >> 8) == 0xc0) { //uses (EC)DHE_ key exchange methods
			receiveKeyExchange();
		}
		receiveHelloDone();

		const std::vector<byte> clientPublicKey = generateKeyPair();
		sendClientKeyExchange(clientPublicKey);

		generateMasterSecret();
		sendChangeCipherSpec();
		sendClientFinish();

		receiveChangeCipherSpec();
		receiveServerFinish();
	}

private:
	const SOCKET m_socket;

	struct ConnectionData {
		ConnectionData() : handshakeHash(BCRYPT_SHA256_ALGORITHM) {}

		std::vector<byte> clientRandom;
		std::vector<byte> serverRandom;
		//std::vector<byte> serverCertificate;
		std::vector<byte> serverPublickey;
		uint16_t cipher;
		BCRYPT_KEY_HANDLE clientKeyHandle;

		BCRYPT_KEY_HANDLE sendKey;
		BCRYPT_KEY_HANDLE recvKey;

		std::vector<byte> clientMac;
		std::vector<byte> serverMac;
		std::vector<byte> clientIV;
		std::vector<byte> serverIV;

		RUNNING_HASH handshakeHash;
		std::vector<byte> masterSecret;

		uint64_t send_seq_num = 0; //TODO: increment
		uint64_t recv_seq_num = 0; //TODO: increment
	} connectionData;

	void sendClientHello(const std::string& host) {
		BufferBuilder buf;

		buf.putArray({3, 3}); //TLS 1.2 Client version

		connectionData.clientRandom = getRandomData(32);
		buf.putArray(connectionData.clientRandom);

		buf.put(0); //session id (no session)

		//TODO: AES with CBC is vulnerable
		//cipher suites
		const byte cipher[] = {
			//0x00, 0x9d, // TLS_RSA_WITH_AES_256_GCM_SHA384
			//0x00, 0x9c, // TLS_RSA_WITH_AES_128_GCM_SHA256
			//0xc0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
			0xc0, 0x13 // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
			//0xc0, 0x2b, //TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		};
		const size_t cipherLength = sizeof(cipher);
		buf.putU16(cipherLength);
		buf.putArray(cipher, cipherLength);

		//copmpression methods
		buf.putArray({1, 0});

		//extensions
		{
			BufferBuilder extBuf;

			{
				//SNI extension
				extBuf.putArray({ 0, 0 }); //extension 'server name'
				extBuf.putU16(host.size() + 5);
				extBuf.putU16(host.size() + 3); //only entry length

				extBuf.put(0); //list entry type 'DNS hostname'

				//size + host name string
				extBuf.putU16(host.size());
				extBuf.putArray((byte*)host.data(), host.size());
			}

			{
				//signature algorithms extension
				extBuf.putArray({ 0x00, 0x0d }); //extension 'Signature Algorithms'
				const byte signatureAlgos[] = {
					0x04, 0x01, // RSA/PKCS1/SHA256
					0x05, 0x01, // RSA/PKCS1/SHA386
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

		sendRecord(0x16, 0x1, handshakeBuf.data());
	}

	void receiveServerHello() {
		BufferReader recordBuffer = receiveRecord();
		if (recordBuffer.read() != 0x16) {
			throw std::runtime_error("unexpected record type");
		}

		if (recordBuffer.readU16() != 0x0303) {
			throw std::runtime_error("unexpected tls version");
		}

		const size_t handshakeSize = recordBuffer.readU16();
		BufferReader handshakeBuffer = recordBuffer.readArray(handshakeSize);
		assert(recordBuffer.remaining() == 0);

		if (handshakeBuffer.read() != 0x2) {
			throw std::runtime_error("unexpected message type");
		}
		const size_t serverHelloLength = handshakeBuffer.readU24();

		BufferReader helloBuffer = handshakeBuffer.readArray(serverHelloLength);
		assert(handshakeBuffer.remaining() == 0);
		if (helloBuffer.readU16() != 0x0303) {
			throw std::runtime_error("unexpected tls version");
		}
		connectionData.serverRandom = helloBuffer.readArrayRaw(32);
		const size_t sessionIdLength = helloBuffer.read();
		if (sessionIdLength > 0) {
			helloBuffer.skip(sessionIdLength); //ignore session id
		}
		connectionData.cipher = static_cast<uint16_t>(helloBuffer.readU16());
		std::cout << "cipher: " << ((connectionData.cipher & 0xff00) >> 8) << ' ' << (connectionData.cipher & 0xff) << '\n';
		if (helloBuffer.read() != 0) {
			throw std::runtime_error("unexpected compression method");
		}
		if (helloBuffer.remaining() > 0) {
			const size_t extensionLength = helloBuffer.readU16();
			std::cout << extensionLength << " bytes of extension data\n";
		}
	}

	void receiveCertificate() {
		BufferReader recordBuffer = receiveRecord();
		if (recordBuffer.read() != 0x16) {
			throw std::runtime_error("unexpected record type");
		}

		if (recordBuffer.readU16() != 0x0303) {
			throw std::runtime_error("unexpected tls version");
		}

		const size_t handshakeSize = recordBuffer.readU16();
		BufferReader handshakeBuffer = recordBuffer.readArray(handshakeSize);
		assert(recordBuffer.remaining() == 0);

		if (handshakeBuffer.read() != 0x0b) {
			throw std::runtime_error("unexpected message type");
		}
		const size_t certificatesLength = handshakeBuffer.readU24();
		size_t bytesHandled = 0;
		while (bytesHandled < certificatesLength) {
			const size_t certLength = handshakeBuffer.readU24();
			bytesHandled += 3;

			handshakeBuffer.skip(certLength);
			bytesHandled += certLength;
		}
	}

	void receiveKeyExchange() {
		BufferReader recordBuffer = receiveRecord();
		if (recordBuffer.read() != 0x16) {
			throw std::runtime_error("unexpected record type");
		}

		if (recordBuffer.readU16() != 0x0303) {
			throw std::runtime_error("unexpected tls version");
		}

		const size_t handshakeSize = recordBuffer.readU16();
		BufferReader handshakeBuffer = recordBuffer.readArray(handshakeSize);
		assert(recordBuffer.remaining() == 0);

		if (handshakeBuffer.read() != 0x0c) {
			throw std::runtime_error("unexpected message type");
		}
		const size_t keyInfoSize = handshakeBuffer.readU24();
		BufferReader keyInfoBuffer = handshakeBuffer.readArray(keyInfoSize);

		const size_t curveType = keyInfoBuffer.read();
		if (curveType != 3) { //only support 'named_curve'
			throw std::runtime_error("unsupported curve type");
		}
		const size_t curve = keyInfoBuffer.readU16();
		if (curve != 0x001d) { //only suport x25519 curve
			throw std::runtime_error("unsupported curve");
		}

		const size_t publicKeyLength = keyInfoBuffer.read();
		connectionData.serverPublickey = keyInfoBuffer.readArrayRaw(publicKeyLength);

		//signature, not check in this implementation
		keyInfoBuffer.skip(2); //SignatureAndHashAlgorithm (RFC5246 7.4.1.4.1)
		const size_t signatureLength = keyInfoBuffer.readU16();
		keyInfoBuffer.skip(signatureLength);
		assert(keyInfoBuffer.remaining() == 0);
	}

	void receiveHelloDone() {
		BufferReader recordBuffer = receiveRecord();
		if (recordBuffer.read() != 0x16) {
			throw std::runtime_error("unexpected record type");
		}

		if (recordBuffer.readU16() != 0x0303) {
			throw std::runtime_error("unexpected tls version");
		}

		const size_t handshakeSize = recordBuffer.readU16();
		BufferReader handshakeBuffer = recordBuffer.readArray(handshakeSize);
		assert(recordBuffer.remaining() == 0);

		if (handshakeBuffer.read() != 0x0e) {
			throw std::runtime_error("unexpected message type");
		}
		const size_t emptySize = handshakeBuffer.readU24();
		if(emptySize != 0) {
			throw std::runtime_error("unexpected data in Server Hello Done");
		}
	}

	//generates a x25519 curve private/public key pair, stores the key handle in connectionData and returns the raw public key bytes
	std::vector<byte> generateKeyPair() {
		BCRYPT_ALG_HANDLE hAlg = nullptr;
		NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_ALGORITHM, NULL, 0);
		if (status != 0) {
			throw std::runtime_error("Could not open curve x25519 provider");
		}

		status = BCryptSetProperty(hAlg, BCRYPT_ECC_CURVE_NAME, (PUCHAR)BCRYPT_ECC_CURVE_25519, sizeof(BCRYPT_ECC_CURVE_25519), 0);
		if (status != 0) {
			throw std::runtime_error("Could not set curve parameter");
		}

		connectionData.clientKeyHandle = nullptr;
		status = BCryptGenerateKeyPair(hAlg, &connectionData.clientKeyHandle, 255, 0);
		if (status != 0) {
			throw std::runtime_error("Could not generate key pair");
		}

		status = BCryptFinalizeKeyPair(connectionData.clientKeyHandle, 0);
		if (status != 0) {
			throw std::runtime_error("Could not finalize key pair");
		}

		ULONG pcbResult = 0;
		status = BCryptExportKey(connectionData.clientKeyHandle, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &pcbResult, 0);
		if (status != 0) {
			throw std::runtime_error("Could not export public key");
		}

		std::vector<byte> publicKey(pcbResult, 0);

		status = BCryptExportKey(connectionData.clientKeyHandle, 0, BCRYPT_ECCPUBLIC_BLOB, publicKey.data(), publicKey.size(), &pcbResult, 0);
		if (status != 0) {
			throw std::runtime_error("Could not export public key");
		}

		BufferReader tmpReader(publicKey);
		tmpReader.skip(4); //dwMagic
		const size_t cbKey = htonl(tmpReader.readU32());
		std::vector<byte> rawPublicKey = tmpReader.readArrayRaw(cbKey);

		closeAlgorithm(hAlg);

		return rawPublicKey;
	}

	std::vector<byte> prf(const std::string& label, const std::vector<byte>& seed, const size_t outputLength, const std::vector<byte>& masterSecret) {
		const std::vector<byte> labelVec(begin(label), end(label));
		
		HMAC hmac(BCRYPT_SHA256_ALGORITHM);
		hmac.setSecret(masterSecret);

		std::vector<byte> outBuffer;

		auto A_buffer = hmac.getHash(labelVec, seed); //a1
		while (outBuffer.size() < outputLength) {
			const auto tmpBuffer = hmac.getHash(A_buffer, labelVec, seed); //p1
			outBuffer.insert(end(outBuffer), begin(tmpBuffer), begin(tmpBuffer) + min(tmpBuffer.size(), outputLength - outBuffer.size()));
			A_buffer = hmac.getHash(A_buffer);
		}

		return outBuffer;
	}

	void generateMasterSecret() {
		BCRYPT_ALG_HANDLE hAlg = nullptr;
		NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_ALGORITHM, NULL, 0);
		if (status != 0) {
			throw std::runtime_error("Could not open curve x25519 provider");
		}

		status = BCryptSetProperty(hAlg, BCRYPT_ECC_CURVE_NAME, (PUCHAR)BCRYPT_ECC_CURVE_25519, sizeof(BCRYPT_ECC_CURVE_25519), 0);
		if (status != 0) {
			throw std::runtime_error("Could not set curve parameter");
		}

		BufferBuilder publicKeyBuf;
		publicKeyBuf.putU32(htonl(BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC));
		publicKeyBuf.putU32(htonl(connectionData.serverPublickey.size()));
		publicKeyBuf.putArray(connectionData.serverPublickey);

		{
			//expand buffer with zeros to a size of 0x48 bytes.
			std::vector<byte> tmp(0x48 - publicKeyBuf.size(), 0);
			publicKeyBuf.putArray(tmp);
		}

		BCRYPT_KEY_HANDLE serverKeyHandle = nullptr;
		status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &serverKeyHandle, (PUCHAR)publicKeyBuf.data().data(), publicKeyBuf.size(), 0);
		if (status != 0) {
			throw std::runtime_error("Could not import server public key");
		}

		BCRYPT_SECRET_HANDLE preMasterSecret = nullptr;
		status = BCryptSecretAgreement(connectionData.clientKeyHandle, serverKeyHandle, &preMasterSecret, 0);
		if (status != 0) {
			throw std::runtime_error("Could not generate pre master secret");
		}

		BCryptBuffer keyGenDescData[4];

		keyGenDescData[0].BufferType = KDF_TLS_PRF_LABEL;
		const std::string masterSecretStr("master secret");
		keyGenDescData[0].cbBuffer = masterSecretStr.size(); // 'master secret' length
		keyGenDescData[0].pvBuffer = (PVOID)masterSecretStr.data();

		std::vector<byte> seed;
		seed.insert(end(seed), begin(connectionData.clientRandom), end(connectionData.clientRandom));
		seed.insert(end(seed), begin(connectionData.serverRandom), end(connectionData.serverRandom));
		assert(seed.size() == 64);
		keyGenDescData[1].BufferType = KDF_TLS_PRF_SEED;
		keyGenDescData[1].cbBuffer = seed.size();
		keyGenDescData[1].pvBuffer = seed.data();

		DWORD protocolVersion = 0x0303; // TLS1_2_PROTOCOL_VERSION
		keyGenDescData[2].BufferType = KDF_TLS_PRF_PROTOCOL;
		keyGenDescData[2].cbBuffer = sizeof(DWORD);
		keyGenDescData[2].pvBuffer = &protocolVersion;

		keyGenDescData[3].BufferType = KDF_HASH_ALGORITHM;
		keyGenDescData[3].cbBuffer = sizeof(BCRYPT_SHA256_ALGORITHM)+1; // Length of 'SHA256' / 'SHA384'
		keyGenDescData[3].pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM; //defaults to SHA256

		//https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey

		BCryptBufferDesc keyGenDesc;
		keyGenDesc.ulVersion = BCRYPTBUFFER_VERSION;
		keyGenDesc.cBuffers = 4; //Number of keyGenDescData elements
		keyGenDesc.pBuffers = keyGenDescData;

		ULONG bufferSize = 0;
		status = BCryptDeriveKey(preMasterSecret, BCRYPT_KDF_TLS_PRF, &keyGenDesc, nullptr, 0, &bufferSize, 0);
		if (status != 0) {
			throw std::runtime_error("Could not generate master secret");
		}

		assert(bufferSize == 0x30);
		connectionData.masterSecret.resize(bufferSize, 0);
		status = BCryptDeriveKey(preMasterSecret, BCRYPT_KDF_TLS_PRF, &keyGenDesc, connectionData.masterSecret.data(), connectionData.masterSecret.size(), &bufferSize, 0);
		if (status != 0) {
			throw std::runtime_error("Could not generate master secret");
		}
		
		//https://github.com/NetworkState/cwitch/blob/55f8fabcf6cdf2f3afe9e9f26dcd8bd0e30a5db0/tls12.h#L88
		{
			BufferBuilder seedPRF(64);
			seedPRF.putArray(connectionData.serverRandom);
			seedPRF.putArray(connectionData.clientRandom);

			const size_t macKeySize = 20; //mac key, 2x 20 bytes for SHA1 and 2x 32 bytes for SHA256. 0 for AES GCM mode!?
			const size_t encKeySize = 16; //enc_key_length, 2x 16 bytes for AES 128 and 2x 32 bytes for AES 256
			const size_t ivLength = 0; //fixed_iv_length, 2x 16 bytes. TODO: why 16 bytes?, 0 for AES_CBC?
			const size_t expansionSize = 2 * macKeySize + 2 * encKeySize + 2 * ivLength;
			const auto keyExpansion = prf("key expansion", seedPRF.data(), expansionSize, connectionData.masterSecret);
			BufferReader reader(keyExpansion);

			if (macKeySize > 0) {
				connectionData.clientMac = reader.readArrayRaw(macKeySize);
				connectionData.serverMac = reader.readArrayRaw(macKeySize);
			}
			if (encKeySize > 0) {
				BCRYPT_ALG_HANDLE aesAlgorithm;
				NTSTATUS status = BCryptOpenAlgorithmProvider(&aesAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
				if (status != 0) {
					throw std::runtime_error("could not open AES algorithm");
				}
				status = BCryptSetProperty(aesAlgorithm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
				if (status != 0) {
					throw std::runtime_error("could not set caining mode");
				}

				{
					const auto keyData = reader.readArrayRaw(encKeySize);
					status = BCryptGenerateSymmetricKey(aesAlgorithm, &connectionData.sendKey, NULL, 0, (PUCHAR)keyData.data(), keyData.size(), 0);
					if (status != 0) {
						throw std::runtime_error("could not import AES key");
					}
				}

				{
					const auto keyData = reader.readArrayRaw(encKeySize);
					status = BCryptGenerateSymmetricKey(aesAlgorithm, &connectionData.recvKey, NULL, 0, (PUCHAR)keyData.data(), keyData.size(), 0);
					if (status != 0) {
						throw std::runtime_error("could not import AES key");
					}
				}
			}
			if (ivLength > 0) {
				connectionData.clientIV = reader.readArrayRaw(ivLength);
				connectionData.serverIV = reader.readArrayRaw(ivLength);
			}

		}

		closeAlgorithm(hAlg);
	}

	std::vector<byte> encrypt(const std::vector<byte>& data, const byte messageType, const std::vector<byte>& iv) const {
		BufferBuilder encryptContent;
		encryptContent.putArray(data);

		//MAC
		{
			BufferBuilder macInput;
			macInput.putU64(connectionData.send_seq_num);
			macInput.put(messageType); //message type
			macInput.putArray({3, 3}); //version, TLS 1.2
			macInput.putU16(data.size());

			HMAC sha1(BCRYPT_SHA1_ALGORITHM);
			sha1.setSecret(connectionData.clientMac);
			const std::vector<byte> hash = sha1.getHash(macInput.data(), data);
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
		NTSTATUS status = BCryptEncrypt(connectionData.sendKey, (PUCHAR)encryptContent.data().data(), encryptContent.size(), NULL, (PUCHAR)iv.data(), iv.size(), NULL, 0, &outSize, 0);
		if (status != 0) {
			std::runtime_error("could not encrypt data");
		}
		std::vector<byte> outBuf(outSize, 0);
		status = BCryptEncrypt(connectionData.sendKey, (PUCHAR)encryptContent.data().data(), encryptContent.size(), NULL, (PUCHAR)iv.data(), iv.size(), outBuf.data(), outBuf.size(), &outSize, 0);
		if (status != 0) {
			std::runtime_error("could not encrypt data");
		}

		return outBuf;
	}

	std::vector<byte> decrypt(const std::vector<byte>& data, const byte messageType, const std::vector<byte>& iv) {
		ULONG outSize = 0;
		NTSTATUS status = BCryptDecrypt(connectionData.recvKey, (PUCHAR)data.data(), data.size(), NULL, (PUCHAR)iv.data(), iv.size(), NULL, 0, &outSize, 0);
		if (status != 0) {
			std::runtime_error("could not decrypt data");
		}
		std::vector<byte> outBuf(outSize, 0);
		status = BCryptDecrypt(connectionData.recvKey, (PUCHAR)data.data(), data.size(), NULL, (PUCHAR)iv.data(), iv.size(), outBuf.data(), outBuf.size(), &outSize, 0);
		if (status != 0) {
			std::runtime_error("could not decrypt data");
		}

		//remove padding
		const auto paddingLength = outBuf.back();
		outBuf.resize(outBuf.size() - (paddingLength+1));

		const size_t macSize = 20; //hash size for HMAC-SHA1
		const size_t payloadSize = outBuf.size() - macSize;
		const std::vector<byte> payload(outBuf.begin(), outBuf.begin() + payloadSize);

		//MAC
		{
			const std::vector<byte> mac(outBuf.end()-macSize, outBuf.end());

			//CHECK MAC
			HMAC sha1(BCRYPT_SHA1_ALGORITHM);
			sha1.setSecret(connectionData.serverMac);

			BufferBuilder macInput;
			macInput.putU64(connectionData.recv_seq_num);
			macInput.put(messageType); //message type
			macInput.putArray({ 3, 3 }); //version, TLS 1.2
			macInput.putU16(payloadSize);

			const auto computedMac = sha1.getHash(macInput.data(), payload);
			if (mac != computedMac) {
				throw std::runtime_error("Received MAC is corrupted");
			}
		}

		return payload;
	}

	void sendClientKeyExchange(const std::vector<byte>& publicKey) {
		BufferBuilder handshakeBuf;
		handshakeBuf.put(0x10); //handshake message type 'client key exchange'
		handshakeBuf.putU24(1 + publicKey.size()); //1 + n bytes of public key data follows

		handshakeBuf.put(static_cast<byte>(publicKey.size())); //key length
		handshakeBuf.putArray(publicKey);

		sendRecord(0x16, 0x3, handshakeBuf.data());
	}

	void sendChangeCipherSpec() {
		sendRecord(0x14, 0x3, { 1 }); //0x14 = type ChangeCipherSpec record
	}

	void sendClientFinish() {
		const size_t iv_size = 16; //record_iv_length = block_size = 16 for AES
		const auto iv = getRandomData(iv_size);

		BufferBuilder buf;
		buf.putArray(iv);

		//verify data
		{
			BufferBuilder verifyBuilder;
			verifyBuilder.put(0x14); //finish message
			RUNNING_HASH handshakeHashCopy(connectionData.handshakeHash); //copy hash object, so we can get the current hash and can continue to use the old hashobject adn add the clientFinish message to it
			const auto handshakeHash = handshakeHashCopy.finish();
			const size_t verifyLength = 12;
			const auto verifyData = prf("client finished", handshakeHash, verifyLength, connectionData.masterSecret);
			verifyBuilder.putU24(verifyLength);
			verifyBuilder.putArray(verifyData);

			connectionData.handshakeHash.addData(verifyBuilder.data());

			const auto encryptedData = encrypt(verifyBuilder.data(), 0x16, iv); //handshake record type
			buf.putArray(encryptedData);
		}

		sendRecord(0x16, 0x3, buf.data(), false); //handshake record
	}

	void receiveChangeCipherSpec() {
		BufferReader reader = receiveRecord();
		if (reader.read() != 0x14) {
			throw std::runtime_error("Did not receive server change cipherSpec");
		}
		if (reader.readU16() != 0x0303) {
			throw std::runtime_error("unexpected tls version");
		}
		const auto length = reader.readU16();
		auto payload = reader.readArray(length);
		if (payload.bufferSize() != 1 || payload.read() != 0x1) {
			throw std::runtime_error("wrong server change cipherSpec payload");
		}
	}

	void receiveServerFinish() {
		BufferReader reader = receiveRecord(false);
		if (reader.read() != 0x16) {
			throw std::runtime_error("unexpected record type");
		}

		if (reader.readU16() != 0x0303) {
			throw std::runtime_error("unexpected tls version");
		}
		const size_t payloadSize = reader.readU16();
		BufferReader payload = reader.readArray(payloadSize);
		const auto iv = payload.readArrayRaw(16); //record_iv_length = block_size = 16 for AES
		const auto decryptData = payload.readArrayRaw(payloadSize - iv.size());

		auto verifyRecord = BufferReader(decrypt(decryptData, 0x16, iv)); //0x16 record type = handshake
		if (verifyRecord.read() != 0x14) {
			throw std::runtime_error("unexpected record type");
		}
		const auto verifyLength = verifyRecord.readU24();
		const auto verifyData = verifyRecord.readArrayRaw(verifyLength);

		//compute verify data
		{
			const auto handshakeHash = connectionData.handshakeHash.finish();
			const auto computedVerify = prf("server finished", handshakeHash, verifyLength, connectionData.masterSecret);

			if (computedVerify != verifyData) {
				throw std::runtime_error("verify data corrupted");
			}
		}

	}

	void sendRecord(const byte type, const byte subVersion, const std::vector<byte>& data, const bool addToHash = true) {
		if (type == 0x16 && addToHash) { //handshake record
			connectionData.handshakeHash.addData(data);
		}
		
		BufferBuilder buf(5);
		buf.put(type);
		buf.putArray({3, subVersion }); //TLS version 1.subVersion
		buf.putU16(data.size());

		{ //hexdump send data
			std::vector<byte> tmp;
			tmp.insert(end(tmp), begin(buf.data()), end(buf.data()));
			tmp.insert(end(tmp), begin(data), end(data));
			hexdump(tmp.data(), tmp.size());
		}

		sendData(buf.data());
		sendData(data);
	}

	void sendData(const std::vector<byte>& data) const {
		size_t bytesSend = 0;
		do {
			int result = send(m_socket, (char*)data.data() + bytesSend, data.size() - bytesSend, 0);
			if (result < 0) {
				std::cerr << "Error sending data: " << WSAGetLastError() << '\n';
				throw std::runtime_error("error sending data");
			}
			bytesSend += result;
		} while (bytesSend < data.size());
	}

	BufferReader receiveRecord(const bool addToHash = true) {
		byte header[5]{ 0 };
		size_t bytesReceived = 0;
		do {
			int headerStatus = recv(m_socket, (char*)header, 5, 0);
			if (headerStatus == 0) {
				throw std::runtime_error("Connection closed");
			}else if (headerStatus < 0) {
				throw std::runtime_error("recv failed, check 'WSAGetLastError()'");
			}else {
				bytesReceived += headerStatus;
			}
		} while (bytesReceived < 5);

		const size_t msgLength = (static_cast<size_t>(header[3]) << 8) | header[4];
		std::vector<byte> msgContent(msgLength, 0);
		bytesReceived = 0;
		do {
			int status = recv(m_socket, (char*)msgContent.data() + bytesReceived, msgLength - bytesReceived, 0);
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

		if (header[0] == 0x16 && addToHash) { //check for handshake record
			connectionData.handshakeHash.addData(msgContent);
		}

		msgContent.insert(begin(msgContent), header, header + 5); //prepend message header
		hexdump(msgContent.data(), msgContent.size());
		return BufferReader(msgContent);
	}

	std::vector<byte> getRandomData(const size_t length) const {
		std::vector<byte> buf(length, 0);

		BCRYPT_ALG_HANDLE hAlg = nullptr;
		NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
		if(status < 0) {
			throw std::runtime_error("Could not open random provider");
		}

		status = BCryptGenRandom(hAlg, buf.data(), length, 0);
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

	void hexdump(const void *ptr, const int buflen) const {
		unsigned char *buf = (unsigned char*)ptr;
		int i, j;
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
#pragma once
#include "BufferHandler.h"
#include "Certificate.h"
#include <iomanip>
#include <sstream>
#include <immintrin.h>

class CertReader {
public:

	CertReader(BufferReader& reader)
		: m_reader(reader)
	{
		parseCert();
	}

	const Certificate& getCertificate() const noexcept
	{
		return m_certificate;
	}


private:
	Certificate m_certificate;

	struct IdentHeader
	{
		byte tagClass;
		bool isPrimitive;
		byte tagType;
		size_t tagLength;
	};

	IdentHeader readHeader(size_t& bytesLeft) {
		IdentHeader header = {};

		if (bytesLeft < 1) {
			throw std::runtime_error("Unexpected end of certificate");
		}

		const auto type = m_reader.read(); bytesLeft--;

		header.tagClass = (type & 0xc0) >> 6;
		header.isPrimitive = ((type & 0x20) >> 5) == 0;
		header.tagType = type & 0x1F;

		if (header.tagType == 0x1f) {
			// long form tag type
			// TODO: implement
			assert(false);
		}

		const auto firstLength = m_reader.read(); bytesLeft--;
		if ((firstLength >> 7) != 0) {
			// long length encoding
			const size_t numLengthBytes = firstLength & 0x7f;
			for (size_t i = 0; i < numLengthBytes; i++) {
				if (bytesLeft == 0) {
					throw std::runtime_error("Unexpected end of certificate");
				}
				header.tagLength <<= 8;
				header.tagLength |= m_reader.read(); bytesLeft--;
			}
		}else {
			header.tagLength = static_cast<size_t>(firstLength);
		}

		if (header.tagLength > bytesLeft) {
			throw std::runtime_error("Unexpected end of certificate");
		}

		return header;
	}

	void parseCert() {

		// get global sequence + length
		// left is the amound left in the read, not the size of this certificate
		size_t left = m_reader.remaining();
		const IdentHeader certHeader = readHeader(left);

		if (certHeader.tagClass != 0/*universal*/ || certHeader.isPrimitive || certHeader.tagType != 16/*sequence*/) {
			// invalid certificate
			throw std::runtime_error("Invalid certificate start");
		}
		size_t certLength = certHeader.tagLength;

		// read TBSCertificate (the signed certificate data)
		{
			const byte* signedPartStart = m_reader.posPtr();
			const IdentHeader tbsHeader = readHeader(certLength);
			if (tbsHeader.tagClass != 0/*universal*/ || tbsHeader.isPrimitive || tbsHeader.tagType != 16/*sequence*/) {
				// invalid TBSCertificate
				throw std::runtime_error("Invalid TBSCertificate start");
			}
			size_t tbsSize = tbsHeader.tagLength;

			// read version if present
			size_t certificateVersion = 1; // default is 1
			{
				size_t tbsSizeBackup = tbsSize;
				m_reader.mark();
				const IdentHeader maybeVersionHeader = readHeader(tbsSize);
				if (maybeVersionHeader.tagClass == 2/*Context-specific*/ && !maybeVersionHeader.isPrimitive && maybeVersionHeader.tagType == 0) {
					// found certificate version
					certificateVersion = readInteger(tbsSize) + 1;
				}else {
					// no certificate version, reset read bytes
					m_reader.reset();
					tbsSize = tbsSizeBackup;
				}
			}
			
			// read serial number
			// TODO: serial num can be bigger than 8 bytes, handle that
			const size_t serialNum = readInteger(tbsSize);

			// read signature algorithm
			m_certificate.caAlgorithm = readAlgorithm(tbsSize);

			// read certificate issuer
			m_certificate.issuer = readName(tbsSize);

			// read certificate validity
			readValidity(tbsSize);

			m_certificate.subject = readName(tbsSize);

			readPublicKey(tbsSize);

			if (certificateVersion > 1 && tbsSize > 0) {
				// Read the three optional fields, we ignore issuerUniqueID and subjectUniqueID, but parse the extensions
				while (tbsSize > 0) {
					const auto header = readHeader(tbsSize);
					if (header.tagClass != 2/*Context-specific*/ || header.isPrimitive) {
						throw std::runtime_error("Unexpected field type");
					}
					if (header.tagType == 3 /*extensions*/) {
						size_t extensionsLength = header.tagLength;

						const auto extensionsSequenceHeader = readHeader(extensionsLength);
						if (extensionsSequenceHeader.tagClass != 0/*universal*/ || extensionsSequenceHeader.isPrimitive || extensionsSequenceHeader.tagType != 16/*sequence*/) {
							// invalid extension
							throw std::runtime_error("Invalid extension sequence");
						}
						
						// read all extensions
						while (extensionsLength > 0) {
							const auto extensionHeader = readHeader(extensionsLength);
							if (extensionHeader.tagClass != 0/*universal*/ || extensionHeader.isPrimitive || extensionHeader.tagType != 16/*sequence*/) {
								// invalid extension
								throw std::runtime_error("Invalid extension type");
							}

							const uint32_t extensionOid = readHashedOid(extensionsLength);

							// Critical field is optional, defaults to false
							const bool isCritical = readBoolOptional(extensionsLength, false);

							const auto contentHeader = readHeader(extensionsLength);
							if (contentHeader.tagClass != 0/*universal*/ || contentHeader.tagType != 4/*octed string*/) {
								// invalid octed string
								throw std::runtime_error("Invalid octed string header");
							}
							size_t contentLength = contentHeader.tagLength;
							extensionsLength -= contentLength;

							switch (extensionOid)
							{
							case 1890530366: //basicConstraints
								{
								const auto constrainsHeader = readHeader(contentLength);
								if (constrainsHeader.tagClass != 0/*universal*/ || constrainsHeader.isPrimitive || constrainsHeader.tagType != 16/*sequence*/) {
									// invalid sequence header
									throw std::runtime_error("Invalid basic constrains sequence header");
								}
								m_certificate.basicConstrainsExt.cA = readBoolOptional(contentLength, false);
								if (m_certificate.basicConstrainsExt.cA) {
									m_certificate.basicConstrainsExt.pathLenConstraint = static_cast<size_t>(-1);
									if (contentLength > 0) {
										m_certificate.basicConstrainsExt.pathLenConstraint = readInteger(contentLength);
									}
								}

								}
								assert(contentLength == 0);
								break;
							case 766655617: // keyUsage
								{
								m_certificate.keyUsageExt.usage = 0;
								const auto keyUsageFlags = readBitString(contentLength);
								assert(!keyUsageFlags.empty());
								m_certificate.keyUsageExt.usage |= keyUsageFlags.front() & (1 << 0) ? KeyUsage::SIGNATURE : 0;
								m_certificate.keyUsageExt.usage |= keyUsageFlags.front() & (1 << 5) ? KeyUsage::CERT_SIGNING : 0;
								}
								assert(contentLength == 0);
								break;
							default:
								if (isCritical) {
									throw std::runtime_error("Unkown critical extension in certificate");
								}
								m_reader.skip(contentLength);
								break;
							}
						}
					}else {
						// Skip issuerUniqueID and subjectUniqueID
						m_reader.skip(header.tagLength);
					}
					tbsSize -= header.tagLength;
				}
			}

			assert(tbsSize == 0);
			certLength -= tbsHeader.tagLength;

			const byte* signedPartEnd = m_reader.posPtr();

			LPCWSTR hashAlgo = nullptr;
			switch (m_certificate.caAlgorithm)
			{
			case Algorithm::SHA256:
				hashAlgo = BCRYPT_SHA256_ALGORITHM;
				break;
			case Algorithm::SHA512:
				hashAlgo = BCRYPT_SHA512_ALGORITHM;
				break;
			default:
				throw std::runtime_error("Unsuported hash algorithm");
			}

			RUNNING_HASH hashFunc(hashAlgo);
			hashFunc.addData(signedPartStart, signedPartEnd - signedPartStart);
			m_certificate.signedHash = hashFunc.finish();
		}

		// read signature algorithm
		const Algorithm caSignatureAlgorithm = readAlgorithm(certLength);
		if (m_certificate.caAlgorithm != caSignatureAlgorithm) {
			throw std::runtime_error("Diffrent signature algorithms found");
		}

		m_certificate.caSignature = readBitString(certLength);
		assert(certLength == 0);
	}

	// returns a Algorithm / AlgorithmIdentifier(ASN.1)
	Algorithm readAlgorithm(size_t& bytesLeft) {
		const IdentHeader algorithmHeader = readHeader(bytesLeft);
		if (algorithmHeader.tagClass != 0/*universal*/ || algorithmHeader.isPrimitive || algorithmHeader.tagType != 16/*sequence*/) {
			// invalid signature
			throw std::runtime_error("Invalid signature type");
		}
		size_t signatureLength = algorithmHeader.tagLength;

		const uint32_t algorithmOid = readHashedOid(signatureLength);

		const IdentHeader parametersHeader = readHeader(signatureLength);
		if (parametersHeader.tagLength > 0) {
			// TODO: Reader additional parameter for the algorithm
			assert(false); // TODO: implement
			m_reader.skip(parametersHeader.tagLength);
			signatureLength -= parametersHeader.tagLength;
		}

		bytesLeft -= algorithmHeader.tagLength;

		switch (algorithmOid)
		{
		case 148778961: // rsaEncryption
			return Algorithm::RSA_ENCRYPTION;
		case 1167974401: // sha512WithRSAEncryption
			return Algorithm::SHA512;
		case 1664878569: // sha256WithRSAEncryption
			return Algorithm::SHA256;
		default:
			throw std::runtime_error("unsupported algorithm used");
		}
	}

	CertEntity readName(size_t& bytesLeft) {
		const IdentHeader issuerHeader = readHeader(bytesLeft);
		if (issuerHeader.tagClass != 0/*universal*/ || issuerHeader.isPrimitive || issuerHeader.tagType != 16/*sequence*/) {
			// invalid issuer
			throw std::runtime_error("Invalid issuer type");
		}
		size_t issuerLength = issuerHeader.tagLength;

		CertEntity entries;
		while (issuerLength > 0) {
			const IdentHeader setHeader = readHeader(issuerLength);
			if (setHeader.tagClass != 0/*universal*/ || setHeader.isPrimitive || setHeader.tagType != 17/*set*/) {
				// invalid issuer
				throw std::runtime_error("Invalid issuer set found");
			}

			const IdentHeader sequenceHeader = readHeader(issuerLength);
			if (sequenceHeader.tagClass != 0/*universal*/ || sequenceHeader.isPrimitive || sequenceHeader.tagType != 16/*sequence*/) {
				// invalid issuer
				throw std::runtime_error("Invalid issuer sequence");
			}
			size_t sequenceLength = sequenceHeader.tagLength;

			uint32_t oidIdentifier = 0;
			std::string value;

			while (sequenceLength > 0) {
				m_reader.mark();
				const IdentHeader header = readHeader(sequenceLength); // The header for an OID or its value
				if (header.tagType == 6/*object ident*/) {
					if (header.tagClass != 0/*universal*/ || !header.isPrimitive) {
						throw std::runtime_error("Invalid OID type");
					}
					oidIdentifier = hashBigValue(header.tagLength);
				}else {
					value = readString(header);
				}
				sequenceLength -= header.tagLength;
			}

			switch (oidIdentifier)
			{
			case 370724352: //localityName
				entries.localityName = value;
				break;
			case 1208742436:
				entries.stateOrProvinceName = value;
				break;
			case 1532690896:
				entries.organizationalUnitName = value;
				break;
			case 2838528723:
				entries.organizationName = value;
				break;
			case 3514980639:
				entries.commonName = value;
				break;
			case 3832761603:
				entries.countryName = value;
				break;
			default:
				throw std::runtime_error("Unexpected oid identifier for Name_t");
			}

			issuerLength -= sequenceHeader.tagLength;
		}

		bytesLeft -= issuerHeader.tagLength;

		return entries;
	}

	void readValidity(size_t& bytesLeft) {
		const IdentHeader validityHeader = readHeader(bytesLeft);
		if (validityHeader.tagClass != 0/*universal*/ || validityHeader.isPrimitive || validityHeader.tagType != 16/*sequence*/) {
			throw std::runtime_error("Invalid validity type");
		}

		const auto dateReader = [&]() {
			const IdentHeader dateHeader = readHeader(bytesLeft);
			if (dateHeader.tagType == 23/*UTCTime*/) {

				// https://luca.ntop.org/Teaching/Appunti/asn1.html (see 5.17)
				bytesLeft -= dateHeader.tagLength;
				const auto timeStr = readBigValue<std::string>(dateHeader.tagLength);
				if (timeStr.empty()) {
					throw std::runtime_error("empty time string");
				}

				std::tm timeObj = {};
				timeObj.tm_isdst = -1;
				if (timeStr.back() == 'Z') {
					/* UTC time
					Valid Formats:
					YYMMDDhhmmZ
					YYMMDDhhmm+hh'mm'
					YYMMDDhhmm-hh'mm'
					YYMMDDhhmmssZ
					YYMMDDhhmmss+hh'mm'
					YYMMDDhhmmss-hh'mm'
					*/
					const int yearVal = (timeStr.at(0) - '0') * 10 + (timeStr.at(1) - '0');
					timeObj.tm_year = yearVal < 69 ? yearVal + 100 : yearVal; // [0, 68] maps to 2000-2068, values [69, 99] map to 1969-1999
					timeObj.tm_mon = ((timeStr.at(2) - '0') * 10 + (timeStr.at(3) - '0')) - 1;
					timeObj.tm_mday = (timeStr.at(4) - '0') * 10 + (timeStr.at(5) - '0');

					timeObj.tm_hour = (timeStr.at(6) - '0') * 10 + (timeStr.at(7) - '0');
					timeObj.tm_min = (timeStr.at(8) - '0') * 10 + (timeStr.at(9) - '0');

					if (timeStr.at(10) != 'Z') {
						timeObj.tm_sec = (timeStr.at(10) - '0') * 10 + (timeStr.at(11) - '0');
					}
				}else {
					// times with offsets
					// TODO: implement
					assert(false);
				}

				// normalize:
				return std::mktime(&timeObj);
			}
			else if (dateHeader.tagType == 24/*GeneralizedTime*/) {
				// TODO: Implement
				assert(false);
				return std::time_t{};
			}else {
				throw std::runtime_error("Invalid time type");
			}
		};

		m_certificate.notBeforeValid = dateReader();
		m_certificate.notAfterValid = dateReader();
	}

	void readPublicKey(size_t& bytesLeft) {
		const IdentHeader keyHeader = readHeader(bytesLeft);
		if (keyHeader.tagClass != 0/*universal*/ || keyHeader.isPrimitive || keyHeader.tagType != 16/*sequence*/) {
			throw std::runtime_error("Invalid SubjectPublicKeyInfo type");
		}

		m_certificate.keyAlgorithm = readAlgorithm(bytesLeft);
		assert(m_certificate.keyAlgorithm == Algorithm::RSA_ENCRYPTION);

		const IdentHeader bitStringHeader = readHeader(bytesLeft);
		if (bitStringHeader.tagClass != 0/*universal*/ || bitStringHeader.tagType != 3/*BIT STRING*/) {
			throw std::runtime_error("Invalid BIT STRING type");
		}

		// read the 'unused bits' in the bitstring that encodes the public key. There should be no unused bits
		const auto unusedBits = m_reader.read(); bytesLeft--;
		assert(unusedBits == 0);

		const IdentHeader sequenceHeader = readHeader(bytesLeft);
		if (sequenceHeader.tagClass != 0/*universal*/ || sequenceHeader.tagType != 16/*Sequence*/) {
			throw std::runtime_error("Invalid sequence type in public key");
		}

		const IdentHeader modulusHeader = readHeader(bytesLeft);
		if (modulusHeader.tagClass != 0/*universal*/ || modulusHeader.tagType != 2/*INTEGER*/) {
			throw std::runtime_error("Invalid integer type in modulus");
		}
		auto modulus = readBigValue(modulusHeader.tagLength);
		bytesLeft -= modulusHeader.tagLength;

		while ((modulus.size() % 0x10) && modulus.at(0) == 0) {
			modulus.erase(modulus.begin());
		}

		const IdentHeader expHeader = readHeader(bytesLeft);
		if (expHeader.tagClass != 0/*universal*/ || expHeader.tagType != 2/*INTEGER*/) {
			throw std::runtime_error("Invalid integer type in exponent");
		}
		const auto exponent = readBigValue(expHeader.tagLength);
		bytesLeft -= expHeader.tagLength;

		BCRYPT_ALG_HANDLE algHandle = nullptr;
		NTSTATUS status = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_RSA_ALGORITHM, NULL, 0);
		if (status != 0 || algHandle == nullptr) {
			throw std::runtime_error("Could not open RSA provider");
		}
		std::vector<byte> blobData(sizeof(BCRYPT_RSAKEY_BLOB) + modulus.size() + exponent.size());
		BCRYPT_RSAKEY_BLOB* blob = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(blobData.data());
		const auto modItr = std::copy(exponent.begin(), exponent.end(), std::next(blobData.begin(), sizeof(BCRYPT_RSAKEY_BLOB)));
		std::copy(modulus.begin(), modulus.end(), modItr);
		blob->Magic = BCRYPT_RSAPUBLIC_MAGIC;
		blob->BitLength = static_cast<ULONG>(modulus.size() * 8);
		blob->cbModulus = static_cast<ULONG>(modulus.size());
		blob->cbPublicExp = static_cast<ULONG>(exponent.size());
		blob->cbPrime1 = 0;
		blob->cbPrime2 = 0;

		status = BCryptImportKeyPair(algHandle, nullptr, BCRYPT_PUBLIC_KEY_BLOB, &m_certificate.publicKey, blobData.data(), static_cast<ULONG>(blobData.size()), 0);
		BCryptCloseAlgorithmProvider(algHandle, 0);
		if (status != 0) {
			throw std::runtime_error("Could not import public key");
		}
	}

	size_t readInteger(size_t& bytesLeft) {
		const IdentHeader header = readHeader(bytesLeft);
		if (!header.isPrimitive || header.tagType != 2/*INTEGER*/) {
			throw std::runtime_error("Unexpected identifier, expected INTEGER");
		}

		if (bytesLeft < header.tagLength) {
			throw std::runtime_error("Unexpected end of certificate");
		}

		size_t value = 0;
		for (size_t i = 0; i < header.tagLength; i++) {
			value <<= 8;
			value |= m_reader.read();
		}
		bytesLeft -= header.tagLength;

		return value;
	}

	bool readBool(size_t& bytesLeft) {
		const IdentHeader header = readHeader(bytesLeft);
		if (!header.isPrimitive || header.tagType !=1 /*BOOLEAN*/) {
			throw std::runtime_error("Unexpected identifier, expected BOOLEAN");
		}

		if (bytesLeft < header.tagLength) {
			throw std::runtime_error("Unexpected end of certificate");
		}

		size_t value = 0;
		for (size_t i = 0; i < header.tagLength; i++) {
			value <<= 8;
			value |= m_reader.read();
		}
		bytesLeft -= header.tagLength;

		return value != 0;
	}

	bool readBoolOptional(size_t& bytesLeft, const bool defaultVal) {
		if (bytesLeft < 2) {
			return defaultVal;
		}
		m_reader.mark();
		size_t bytesLeftBackup = bytesLeft;
		const auto maybeBoolHeader = readHeader(bytesLeftBackup);
		m_reader.reset();
		if (maybeBoolHeader.isPrimitive && maybeBoolHeader.tagType == 1 /*BOOLEAN*/) {
			return readBool(bytesLeft);
		}
		return defaultVal;
	}

	template<typename Container = std::vector<byte>>
	Container readBigValue(const size_t numBytes) {
		Container buffer(numBytes, 0);
		for (size_t i = 0; i < numBytes; i++) {
			buffer[i] = m_reader.read();
		}
		return buffer;
	}

	uint32_t hashBigValue(const size_t numBytes) {
		uint32_t hash = 0;
		for (size_t i = 0; i < numBytes; i++) {
			hash = _mm_crc32_u8(hash, m_reader.read());
		}
		return hash;
	}

	uint32_t readHashedOid(size_t& bytesLeft) {
		const auto oidHeader = readHeader(bytesLeft);
		if (oidHeader.tagClass != 0/*universal*/ || !oidHeader.isPrimitive || oidHeader.tagType != 6/*object ident*/) {
			// invalid oid header
			throw std::runtime_error("Invalid oid header");
		}

		bytesLeft -= oidHeader.tagLength;
		return hashBigValue(oidHeader.tagLength);
	}

	std::string readString(const IdentHeader& header) {
		if (header.tagType == 19 /*printable string*/ || header.tagType == 12) {
			// basic ascii
			std::string s(header.tagLength, 0);
			for (size_t i = 0; i < header.tagLength; i++) {
				s[i] = m_reader.read();
			}
			return s;
		}
		else {
			throw std::runtime_error("Unexpected string type");
		}
	}

	std::vector<byte> readBitString(size_t& bytesLeft) {
		const IdentHeader bitStringHeader = readHeader(bytesLeft);
		if (bitStringHeader.tagClass != 0/*universal*/ || bitStringHeader.tagType != 3/*BIT STRING*/) {
			// invalid SubjectPublicKeyInfo
			throw std::runtime_error("Invalid BIT STRING type");
		}
		auto bitString = readBigValue(bitStringHeader.tagLength);
		bytesLeft -= bitStringHeader.tagLength;

		if (bitString.empty()) {
			throw std::runtime_error("empty bitstring key");
		}

		const auto unusedBits = bitString.front();
		bitString.erase(bitString.begin()); // remove 'unusedBits' byte from key
		if (unusedBits != 0) {
			// we need to remove the last 'unusedBits' from the key
			// We simply shift the last byte in 'bitString' by 'unusedBits' to the right
			/*
			Key Bytes:		06 6e 5d c0 (06 => last 6 Bits are unused)
			Raw key bits:	01101110 01011101 11000000
			Desired bits:	01101110 01011101 11
			*/
			bitString.back() >>= unusedBits;
		}

		return bitString;
	}

	BufferReader& m_reader;
};

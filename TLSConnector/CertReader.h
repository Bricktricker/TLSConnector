#pragma once
#include "BufferHandler.h"
#include <unordered_map>
#include <iomanip>
#include <sstream>

class CertReader {
public:

	using Name_t = std::unordered_map<size_t, std::string>;

	enum Algorithm {
		SHA256,
		SHA386,
		SHA512,
		RSA_ENCRYPTION
	};

	struct Certificate
	{
		std::tm notBeforeValid;
		std::tm notAfterValid;

		Name_t subject;
		Name_t issuer; // The one who signed this cert

		Algorithm keyAlgorithm;
		std::vector<byte> publicKey;

		Algorithm caAlgorithm;
		std::vector<byte> caSignature;
	};

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
				// skip the rest of the TBSCertificate. Is the issuerUniqueID, subjectUniqueID and/or the extensions. We don't need them
				m_reader.skip(tbsSize);
				tbsSize = 0;
			}

			assert(tbsSize == 0);
			certLength -= tbsHeader.tagLength;
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

		const IdentHeader algorithmIdHeader = readHeader(signatureLength);
		if (algorithmIdHeader.tagClass != 0/*universal*/ || !algorithmIdHeader.isPrimitive || algorithmIdHeader.tagType != 6/*object ident*/) {
			// invalid signature
			throw std::runtime_error("Invalid signature type");
		}
		const auto algorithmOid = readBigValue(algorithmIdHeader.tagLength);
		signatureLength -= algorithmIdHeader.tagLength;

		const IdentHeader parametersHeader = readHeader(signatureLength);
		if (parametersHeader.tagLength > 0) {
			assert(false); // TODO: implement
			m_reader.skip(parametersHeader.tagLength);
			signatureLength -= parametersHeader.tagLength;
		}

		bytesLeft -= algorithmHeader.tagLength;

		// table of supported signature algorithms
		constexpr std::array<std::pair<Algorithm, std::array<byte, 9>>, 4> algorithmOids = {{
				{ Algorithm::SHA256, {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B} }, // sha256WithRSAEncryption
				{ Algorithm::SHA386, {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C} }, // sha386WithRSAEncryption
				{ Algorithm::SHA512, {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D} },  // sha512WithRSAEncryption
				{ Algorithm::RSA_ENCRYPTION, {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01} } // rsaEncryption
		}};

		const auto itr = std::find_if(begin(algorithmOids), end(algorithmOids), [&algorithmOid](const auto& v) {
			return std::equal(algorithmOid.begin(), algorithmOid.end(), v.second.begin());
		});
		if (itr != end(algorithmOids)) {
			return itr->first;
		}else {
			throw std::runtime_error("unsupported signature algorithm");
		}

	}

	Name_t readName(size_t& bytesLeft) {
		const IdentHeader issuerHeader = readHeader(bytesLeft);
		if (issuerHeader.tagClass != 0/*universal*/ || issuerHeader.isPrimitive || issuerHeader.tagType != 16/*sequence*/) {
			// invalid issuer
			throw std::runtime_error("Invalid issuer type");
		}
		size_t issuerLength = issuerHeader.tagLength;

		Name_t entries;
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

			size_t oidIdentifier = 0;
			std::string value;

			while (sequenceLength > 0) {
				const IdentHeader header = readHeader(sequenceLength); // The header for en OID or its value
				if (header.tagType == 6/*object ident*/) {
					if (header.tagClass != 0/*universal*/ || !header.isPrimitive) {
						throw std::runtime_error("Invalid OID type");
					}
					// https://embeddedinn.xyz/articles/tutorial/understanding-X.509-certificate-structure/#object-identifier-oid
					const auto oid = readBigValue(header.tagLength);
					assert(oid.size() <= 8);
					oidIdentifier = *reinterpret_cast<const size_t*>(oid.data());
				}else {
					value = readString(header);
				}
				sequenceLength -= header.tagLength;
			}
			entries.emplace(oidIdentifier, value);

			issuerLength -= sequenceHeader.tagLength;
		}

		bytesLeft -= issuerHeader.tagLength;

		return entries;
	}

	void readValidity(size_t& bytesLeft) {
		const IdentHeader validityHeader = readHeader(bytesLeft);
		if (validityHeader.tagClass != 0/*universal*/ || validityHeader.isPrimitive || validityHeader.tagType != 16/*sequence*/) {
			// invalid issuer
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

					// normalize:
					const time_t when = std::mktime(&timeObj);
					if (localtime_s(&timeObj, &when) != 0) {
						throw std::runtime_error("localtime_s failed");
					}

				}else {
					// times with offsets
					// TODO: implement
					assert(false);
				}


				return timeObj;
			}
			else if (dateHeader.tagType == 24/*GeneralizedTime*/) {
				// TODO: Implement
				assert(false);
				return std::tm{};
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
			// invalid SubjectPublicKeyInfo
			throw std::runtime_error("Invalid SubjectPublicKeyInfo type");
		}

		m_certificate.keyAlgorithm = readAlgorithm(bytesLeft);
		m_certificate.publicKey = readBitString(bytesLeft);
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

	template<typename Container = std::vector<byte>>
	Container readBigValue(const size_t numBytes) {
		Container buffer(numBytes, 0);
		for (size_t i = 0; i < numBytes; i++) {
			buffer[i] = m_reader.read();
		}
		return buffer;
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
			// TODO: implement
			/*
			Key Bytes:		06 6e 5d c0 (06 => last 6 Bits are unused)
			Raw key bits:	01101110 01011101 11000000
			Desired bits:	01101110 01011101 11
			*/
			assert(false);
		}

		return bitString;
	}

	BufferReader& m_reader;
};

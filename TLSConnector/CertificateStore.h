#pragma once
#include <fstream>
#include <array>
#include <string_view>
#include <cassert>
#include <ctime>
#include "BufferHandler.h"
#include "Crypto.h"
#include "CertReader.h"

class CertificateStore {
public:

	~CertificateStore() {
		std::for_each(m_certificates.begin(), m_certificates.end(), [](const Certificate& cert) {
			const auto status = BCryptDestroyKey(cert.publicKey);
			assert(status == 0);
		});
	}

	void addCertificates(std::istream& reader)
	{
		enum ParseState {
			BEGIN_STR,
			CERT
		};
		
		ParseState currentState = BEGIN_STR;

		// Find end of '-----BEGIN CERTIFICATE-----'
		const auto masksBegin = generateMasks("-----BEGIN CERTIFICATE-----");
		const uint64_t acceptBegin = 1ULL << (27 - 1ULL); // 27 is length of searched string
		uint64_t stateBegin = 0;

		byte char_array_4[4], char_array_3[3];
		int i = 0;
		int j = 0;
		static const std::string_view base64_chars =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz"
			"0123456789+/";

		std::vector<byte> certBuffer;

		while (!reader.eof()) {
			const int val = reader.get();
			if (val == std::char_traits<char>::eof()) {
				return;
			}
			assert(val < 256 && val >= 0);
			std::cout << static_cast<char>(val);
			if (val == '\n' || val == '\r') {
				continue;
			}

			if (currentState == BEGIN_STR) {
				stateBegin = ((stateBegin << 1) | 1) & masksBegin[val];
				if (stateBegin & acceptBegin) {
					currentState = ParseState::CERT;
					i = j = 0;
					certBuffer.clear();
					stateBegin = 0;
				}
			}else if (currentState == ParseState::CERT) {
				if (val == '-') {
					// We reached the end of the base64 encoded certificate
					currentState = BEGIN_STR;
					if (i) {
						for (j = i; j < 4; j++) {
							char_array_4[j] = 0;
						}

						for (j = 0; j < 4; j++) {
							char_array_4[j] = static_cast<byte>(base64_chars.find(char_array_4[j]));
						}

						char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
						char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
						char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

						for (j = 0; (j < i - 1); j++) {
							certBuffer.push_back(char_array_3[j]);
						}
					}

					// Parse the decoded certificate
					BufferWrapper wrapper(certBuffer);
					BufferReader bufferReader(wrapper);
					const CertReader parser(bufferReader);
					m_certificates.push_back(parser.getCertificate());
				}else {
					char_array_4[i++] = static_cast<byte>(val);
					if (i == 4) {
						for (i = 0; i < 4; i++) {
							char_array_4[i] = static_cast<byte>(base64_chars.find(char_array_4[i]));
						}

						char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
						char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
						char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

						for (i = 0; (i < 3); i++) {
							certBuffer.push_back(char_array_3[i]);
						}
						i = 0;
					}
				}
			}
		}
	}

	void addCertificates(const std::string& certFile)
	{
		std::ifstream reader(certFile);
		if (reader.bad() || reader.eof()) {
			throw std::runtime_error("Could not open certificates file");
		}
		addCertificates(reader);
	}

	bool validateCertChain(const std::vector<Certificate>& certs) const {
		const std::time_t currentTime = time(nullptr) - 30000000;
		for (size_t i = 0; i < certs.size(); i++) {
			 const Certificate& cert = certs[i];
			
			// Check if certificate validity timestamp is in currentTime range
			std::tm notBeforeValid = cert.notBeforeValid;
			std::tm notAfterValid = cert.notAfterValid;
			const std::time_t beginTime = std::mktime(&notBeforeValid);
			const std::time_t endTime = std::mktime(&notAfterValid);
			if (beginTime > currentTime || endTime < currentTime) {
				return false;
			}
			
			// Get next certificate in chain
			const Certificate* nextCert = (i + 1) < certs.size() ? &certs[i + 1] : findCert(cert.issuer);
			if (nextCert == nullptr) {
				// Could not find issuer in certificate store
				return false;
			}

			// Check if current validity range is in next cert range
			std::tm nextNotBeforeValid = nextCert->notBeforeValid;
			std::tm nextNotAfterValid = nextCert->notAfterValid;
			const std::time_t nextBeginTime = std::mktime(&nextNotBeforeValid);
			const std::time_t nextEndTime = std::mktime(&nextNotAfterValid);
			if (nextBeginTime > beginTime || nextEndTime < endTime) {
				return false;
			}
			// Check if nextCertificate is still valid
			if (nextBeginTime > currentTime || nextEndTime < currentTime) {
				return false;
			}

			// Validate signature
			BCRYPT_PKCS1_PADDING_INFO paddingInfo = {};
			paddingInfo.pszAlgId = cert.caAlgorithm == Algorithm::SHA256 ? BCRYPT_SHA256_ALGORITHM : BCRYPT_SHA512_ALGORITHM;
			const NTSTATUS status = BCryptVerifySignature(nextCert->publicKey, &paddingInfo,
				(PUCHAR)cert.signedHash.data(), static_cast<ULONG>(cert.signedHash.size()),
				(PUCHAR)cert.caSignature.data(), static_cast<ULONG>(cert.caSignature.size()), BCRYPT_PAD_PKCS1);
			if (status != 0) {
				return false;
			}
		}
		return true;
	}

private:
	constexpr std::array<uint64_t, 256> generateMasks(const std::string_view pattern) const
	{
		std::array<uint64_t, 256> masks = {};
		for (size_t i = 0; i < pattern.size(); i++) {
			const uint8_t c = pattern[i];
			masks[c] |= (1ULL << i);
		}
		return masks;
	}

	const Certificate* findCert(const CertEntity& entity) const {
		assert(m_certificates.size() == 1);
		return &m_certificates.front();
	}

	std::vector<Certificate> m_certificates;
};
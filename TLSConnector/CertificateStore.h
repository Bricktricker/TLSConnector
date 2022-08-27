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
			//std::cout << static_cast<char>(val);
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
				if (val == ' ') {
					continue;
				}
				if (val == '-' || val == '=') {
					// We reached the end of the base64 encoded certificate
					currentState = BEGIN_STR;
					if (i) {
						for (j = i; j < 4; j++) {
							char_array_4[j] = 0;
						}

						for (j = 0; j < 4; j++) {
							const auto pos = base64_chars.find(char_array_4[i]);
							// TODO: Find a better base64 decoder implementation
							// The following assertion fails, if char_array_4[i] is 0.
							// But this implementation ignores it
							//assert(pos != std::string::npos);
							char_array_4[i] = static_cast<byte>(pos);
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
					try {
						const CertReader parser(bufferReader);
						m_certificates.push_back(parser.getCertificate());
					}
					catch (std::exception& e) {
						std::cerr << e.what() << '\n';
					}
				}else {
					char_array_4[i++] = static_cast<byte>(val);
					if (i == 4) {
						for (i = 0; i < 4; i++) {
							const auto pos = base64_chars.find(char_array_4[i]);
							assert(pos != std::string::npos);
							char_array_4[i] = static_cast<byte>(pos);
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

	bool validateCertChain(const std::vector<Certificate>& certs, const std::string& host) const {
		const std::time_t currentTime = time(nullptr);
		for (size_t i = 0; i < certs.size(); i++) {
			 const Certificate& cert = certs[i];
			
			// Check if certificate validity timestamp is in currentTime range
			if (cert.notBeforeValid > currentTime || cert.notAfterValid < currentTime) {
				return false;
			}

			// Check if the send sertificate matches the requested host
			if (i == 0) {
				if (cert.subject.commonName != host) {
					return false;
				}
			}
			
			// Get next certificate in chain
			const Certificate* nextCert = (i + 1) < certs.size() ? &certs[i + 1] : findCert(cert.issuer);
			if (nextCert == nullptr) {
				// Could not find issuer in certificate store
				return false;
			}

			// Check if current certs validity range is in next cert range
			if (nextCert->notBeforeValid > cert.notBeforeValid || nextCert->notAfterValid < cert.notAfterValid) {
				return false;
			}
			// We don't need to check if nextCert is valid, it will always be valid, if the above three checks pass

			// Validate signature
			BCRYPT_PKCS1_PADDING_INFO paddingInfo = {};
			paddingInfo.pszAlgId = cert.hashAlgorithm;
			assert(cert.signAlgorithm == KeyAlgorithm::RSA);

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
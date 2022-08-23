#pragma once
#include <fstream>
#include <array>
#include <string_view>
#include <cassert>
#include "BufferHandler.h"
#include "Crypto.h"
#include "CertReader.h"

class CertificateStore {
public:

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
					const auto cert = parser.getCertificate();

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

	std::vector<Certificate> m_certificates;
};
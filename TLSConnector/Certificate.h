#pragma once
#include <vector>
#include <bcrypt.h>

struct CertEntity {
	std::string countryName;
	std::string stateOrProvinceName;
	std::string localityName;
	std::string organizationName;
	std::string organizationalUnitName;
	std::string commonName;
};

enum KeyAlgorithm {
	RSA
};

struct BasicConstraints {
	size_t pathLenConstraint;
	bool cA;
};

struct KeyUsage {
	enum UsageFlags : byte {
		SIGNATURE = (1 << 0),
		CERT_SIGNING = (1 << 1)
	};
	byte usage;
};

struct Certificate
{
	std::time_t notBeforeValid;
	std::time_t notAfterValid;

	CertEntity subject;
	CertEntity issuer; // The one who signed this cert

	KeyAlgorithm keyAlgorithm;
	BCRYPT_KEY_HANDLE publicKey;

	LPCWSTR hashAlgorithm;
	KeyAlgorithm signAlgorithm;
	std::vector<byte> caSignature;

	std::vector<byte> signedHash;

	// Extensions
	BasicConstraints basicConstrainsExt;
	KeyUsage keyUsageExt;
};

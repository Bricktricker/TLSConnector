#pragma once
#include <vector>
#include <bcrypt.h>

struct CertEntity {
	std::string countryName;
	std::string stateOrProvinceName;
	std::string organizationName;
	std::string organizationalUnitName;
	std::string commonName;
};

enum Algorithm {
	SHA256,
	SHA512,
	RSA_ENCRYPTION
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
	std::tm notBeforeValid;
	std::tm notAfterValid;

	CertEntity subject;
	CertEntity issuer; // The one who signed this cert

	Algorithm keyAlgorithm;
	BCRYPT_KEY_HANDLE publicKey;

	Algorithm caAlgorithm;
	std::vector<byte> caSignature;

	std::vector<byte> signedHash;

	// Extensions
	BasicConstraints basicConstrainsExt;
	KeyUsage keyUsageExt;
};

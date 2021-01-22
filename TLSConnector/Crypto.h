#pragma once
#include <vector>
#include <Windows.h>
#include <bcrypt.h>
#include <assert.h>

class HMAC {
public:
	explicit HMAC(const LPCWSTR _algo)
		:algHandle(nullptr), hashHandle(nullptr), algo(_algo)
	{
		NTSTATUS status = BCryptOpenAlgorithmProvider(&algHandle, algo, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG);
		if (status != 0) {
			throw std::runtime_error("Could not open SHA256 algorithm");
		}
	}

	~HMAC()
	{
		if (hashHandle != nullptr) {
			BCryptDestroyHash(hashHandle);
		}
		
		if (algHandle != nullptr) {
			BCryptCloseAlgorithmProvider(algHandle, 0);
		}
	}

	void setSecret(const std::vector<byte>& secret) {
		NTSTATUS status = BCryptCreateHash(algHandle, &hashHandle, NULL, 0, (PUCHAR)secret.data(), static_cast<ULONG>(secret.size()), BCRYPT_HASH_REUSABLE_FLAG);
		if (status != 0) {
			throw std::runtime_error("Could not create SHA256 hash");
		}
	}

	template <typename ... Args>
	std::vector<byte> getHash(Args&& ... args) {
		assert(hashHandle != nullptr);
		const std::vector<byte> bufferArray[] = { args... };
		for (const std::vector<byte>& buffer : bufferArray) {
			NTSTATUS status = BCryptHashData(hashHandle, (PUCHAR)buffer.data(), buffer.size(), 0);
			if (status != 0) {
				throw std::runtime_error("could not hash data");
			}
		}

		DWORD bytesWritten, hashSize = 0;
		NTSTATUS status = BCryptGetProperty(hashHandle, BCRYPT_HASH_LENGTH, (PUCHAR)&hashSize, sizeof(hashSize), &bytesWritten, 0);
		if (status != 0) {
			throw std::runtime_error("could not hash data");
		}

		std::vector<byte> outBuffer(hashSize, 0);
		status = BCryptFinishHash(hashHandle, (PUCHAR)outBuffer.data(), outBuffer.size(), 0);
		if (status != 0) {
			throw std::runtime_error("could not hash data");
		}

		return outBuffer;
	}

private:
	BCRYPT_ALG_HANDLE algHandle;
	BCRYPT_HASH_HANDLE hashHandle;
	const LPCWSTR algo;
};

class RUNNING_HASH {
public:
	explicit RUNNING_HASH(const LPCWSTR _algo)
		:algHandle(nullptr), hashHandle(nullptr), algo(_algo)
	{
		NTSTATUS status = BCryptOpenAlgorithmProvider(&algHandle, algo, NULL, BCRYPT_HASH_REUSABLE_FLAG);
		if (status != 0) {
			throw std::runtime_error("Could not open HASH algorithm");
		}
		DWORD objSize, bytesWritten = 0;
		status = BCryptGetProperty(algHandle, BCRYPT_OBJECT_LENGTH, (PBYTE)&objSize, sizeof(objSize), &bytesWritten, 0);
		if (status != 0) {
			throw std::runtime_error("Could not get hash size");
		}

		status = BCryptCreateHash(algHandle, &hashHandle, NULL, 0, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
		if (status != 0) {
			throw std::runtime_error("Could not open SHA algorithm");
		}
	}

	RUNNING_HASH(const RUNNING_HASH& other)
		: algHandle(nullptr), hashHandle(nullptr), algo(other.algo) //, hashObject(other.hashObject.size())
	{
		NTSTATUS status = BCryptOpenAlgorithmProvider(&algHandle, algo, NULL, BCRYPT_HASH_REUSABLE_FLAG);
		if (status != 0) {
			throw std::runtime_error("Could not open HASH algorithm");
		}

		status = BCryptDuplicateHash(other.hashHandle, &hashHandle, NULL, 0, 0);
		if (status != 0) {
			throw std::runtime_error("could not copy hash");
		}
	}

	RUNNING_HASH& operator=(const RUNNING_HASH& other) = delete;

	~RUNNING_HASH() {
		if (hashHandle != nullptr) {
			BCryptDestroyHash(hashHandle);
		}
		if (algHandle != nullptr) {
			BCryptCloseAlgorithmProvider(algHandle, 0);
		}
	}

	std::vector<byte> finish() {
		DWORD bytesWritten, hashSize = 0;
		NTSTATUS status = BCryptGetProperty(hashHandle, BCRYPT_HASH_LENGTH, (PUCHAR)&hashSize, sizeof(hashSize), &bytesWritten, 0);
		if (status != 0) {
			throw std::runtime_error("could not hash data");
		}

		std::vector<byte> outBuffer(hashSize, 0);
		status = BCryptFinishHash(hashHandle, (PUCHAR)outBuffer.data(), static_cast<ULONG>(outBuffer.size()), 0);
		if (status != 0) {
			throw std::runtime_error("could not create hash");
		}
		
		return outBuffer;
	}

	void addData(const std::vector<byte>& buffer) {
		NTSTATUS status = BCryptHashData(hashHandle, (PUCHAR)buffer.data(), static_cast<ULONG>(buffer.size()), 0);
		if (status != 0) {
			throw std::runtime_error("could not hash data");
		}
	}

private:
	BCRYPT_ALG_HANDLE algHandle;
	BCRYPT_HASH_HANDLE hashHandle;
	const LPCWSTR algo;
};


#pragma once
#include <vector>

struct BufferBuilder {
	explicit BufferBuilder() = default;
	~BufferBuilder() = default;

	explicit BufferBuilder(const size_t reserve) {
		m_buf.reserve(reserve);
	}

	void put(const byte b) {
		m_buf.push_back(b);
	}

	void putU16(const size_t val) {
		put((val & 0xff00) >> 8);
		put(val & 0xff);
	}

	void putU24(const size_t val) {
		put(static_cast<byte>((val & 0xff0000) >> 16));
		put((val & 0x00ff00) >> 8);
		put(val & 0xff);
	}

	void putU32(const size_t val) {
		put((val & 0xff000000) >> 24);
		put(static_cast<byte>((val & 0x00ff0000) >> 16));
		put((val & 0x0000ff00) >> 8);
		put(val & 0xff);
	}

	void putU64(const uint64_t val) {
		uint64_t mask = static_cast<uint64_t>(0xff) << 56; //highest byte to 1, rest 0
		for (int i = sizeof(val)-1; i >= 0; i--) {
			const auto b = (val & mask) >> (i * 8);
			put(static_cast<byte>(b));
			mask >>= 8;
		}
	}

	void putArray(const std::vector<byte>& arr) {
		m_buf.insert(end(m_buf), begin(arr), end(arr));
	}

	void putArray(std::initializer_list<byte> arr) {
		m_buf.insert(end(m_buf), begin(arr), end(arr));
	}

	void putArray(const byte* start, const size_t length) {
		m_buf.insert(end(m_buf), start, start + length);
	}

	const size_t size() const noexcept {
		return m_buf.size();
	}

	const std::vector<byte>& data() const {
		return m_buf;
	}

private:
	std::vector<byte> m_buf;
};

struct BufferReader {
	explicit BufferReader(const std::vector<byte>& buf) : m_begin(buf.begin()), m_pos(m_begin), m_end(buf.end()) {};
	explicit BufferReader(const std::vector<byte>::const_iterator _begin, const std::vector<byte>::const_iterator _end) : m_begin(_begin), m_pos(m_begin), m_end(_end) {};
	~BufferReader() = default;

	size_t read() {
		const auto v = *m_pos;
		m_pos++;
		return v;
	}

	size_t readU16() {
		const size_t first = read();
		const size_t second = read();
		return (first << 8) | second;
	}

	size_t readU24() {
		const size_t first = read();
		const size_t second = read();
		const size_t third = read();
		return (first << 16) | (second << 8) | third;
	}

	size_t readU32() {
		const size_t first = read();
		const size_t second = read();
		const size_t third = read();
		const size_t fourth = read();
		return (first << 24) | (second << 16) | (third << 8) | fourth;
	}

	BufferReader readArray(const size_t length) {
		if (length > remaining()) {
			throw std::out_of_range("readArray out of bounds");
		}
		const auto begin_array = m_pos;
		m_pos += length;
		return BufferReader(begin_array, m_end);
	}

	std::vector<byte> readArrayRaw(const size_t length) {
		if (length > remaining()) {
			throw std::out_of_range("readArrayRaw out of bounds");
		}
		const std::vector<byte> tmp(m_pos, m_pos + length);
		m_pos += length;
		return tmp;
	}

	void skip(const size_t num) {
		if (num > remaining()) {
			throw std::out_of_range("skip out of bounds");
		}
		m_pos += num;
	}

	size_t remaining() const {
		return std::distance(m_pos, m_end);
	}

	size_t bufferSize() const {
		return std::distance(m_begin, m_end);
	}

	//returns a pointer to the BEGINNING of the given buffer, not the current position
	const byte* data() const {
		return &(*m_begin);
	}

	const byte* posPtr() const {
		return &(*m_pos);
	}
	
private:
	const std::vector<byte>::const_iterator m_begin;
	std::vector<byte>::const_iterator m_pos;
	const std::vector<byte>::const_iterator m_end;
};

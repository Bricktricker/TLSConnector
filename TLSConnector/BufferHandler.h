#pragma once
#include <vector>
#include <cassert>

struct BufferWrapper {
	explicit BufferWrapper(const byte* buf, const size_t size) : m_buf(buf), m_size(size) {}
	explicit BufferWrapper(const std::vector<byte>& vec) : m_buf(vec.data()), m_size(vec.size()) {}

	const byte* data() const noexcept {
		return m_buf;
	}

	size_t size() const noexcept {
		return m_size;
	}

private:
	const byte* m_buf;
	const size_t m_size;
};

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

	void putArray(const BufferWrapper wrapper) {
		m_buf.insert(end(m_buf), wrapper.data(), wrapper.data() + wrapper.size());
	}

	byte* reserve(const size_t numBytes) {
		const auto oldSize = m_buf.size();
		m_buf.resize(oldSize + numBytes, 0);
		return &m_buf[oldSize];
	}

	const size_t size() const noexcept {
		return m_buf.size();
	}

	const std::vector<byte>& data() const {
		return m_buf;
	}

	std::vector<byte>& data() {
		return m_buf;
	}

	BufferWrapper wrapper() const {
		return BufferWrapper(m_buf);
	}

private:
	std::vector<byte> m_buf;
};

struct BufferReader {
	explicit BufferReader(const std::vector<byte>& buf) : m_begin(buf.data()), m_pos(buf.data()), m_end(buf.data() + buf.size()), m_mark(nullptr) {};
	explicit BufferReader(const BufferWrapper wrapper) : m_begin(wrapper.data()), m_pos(wrapper.data()), m_end(wrapper.data() + wrapper.size()), m_mark(nullptr) {};
	explicit BufferReader(const byte* begin, const byte* end) : m_begin(begin), m_pos(begin), m_end(end), m_mark(nullptr) {};
	~BufferReader() = default;

	[[nodiscard]] byte read() {
		const auto v = *m_pos;
		++m_pos;
		return v;
	}

	[[nodiscard]] uint16_t readU16() {
		const uint16_t first = read();
		const uint16_t second = read();
		return (first << 8) | second;
	}

	[[nodiscard]] uint32_t readU24() {
		const uint32_t first = read();
		const uint32_t second = read();
		const uint32_t third = read();
		return (first << 16) | (second << 8) | third;
	}

	[[nodiscard]] uint32_t readU32() {
		const uint32_t first = read();
		const uint32_t second = read();
		const uint32_t third = read();
		const uint32_t fourth = read();
		return (first << 24) | (second << 16) | (third << 8) | fourth;
	}

	[[nodiscard]] BufferReader readArray(const size_t length) {
		if (length > remaining()) {
			throw std::out_of_range("readArray out of bounds");
		}
		const auto begin_array = m_pos;
		m_pos += length;
		return BufferReader(begin_array, m_end);
	}

	[[nodiscard]] std::vector<byte> readArrayRaw(const size_t length) {
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

	[[nodiscard]] size_t remaining() const {
		return std::distance(m_pos, m_end);
	}

	[[nodiscard]] size_t bufferSize() const {
		return std::distance(m_begin, m_end);
	}

	//returns a pointer to the BEGINNING of the given buffer, not the current position
	[[nodiscard]] const byte* data() const {
		return &(*m_begin);
	}

	[[nodiscard]] const byte* posPtr() const {
		return &(*m_pos);
	}

	void mark() {
		m_mark = m_pos;
	}

	void reset() {
		assert(m_mark != nullptr);
		m_pos = m_mark;
	}
	
private:
	const byte* m_begin;
	byte const* m_pos;
	const byte* m_end;
	byte const* m_mark;
};


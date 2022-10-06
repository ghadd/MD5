#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <cstring>
#include <cassert>
#include <cstdint>
#include <functional>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <array>

#include "argparse/argparse.h"

constexpr auto kBitsInByte = 8;
constexpr auto kPaddingBits = 512;
constexpr auto kMessageLengthBits = 64;
constexpr auto kPaddingCongruentBits = kPaddingBits - kMessageLengthBits;
constexpr uint8_t kFirstPaddingByte = 1u << (kBitsInByte - 1);
constexpr uint8_t kPaddingByte = 0u;

constexpr auto S11 = 7;
constexpr auto S12 = 12;
constexpr auto S13 = 17;
constexpr auto S14 = 22;
constexpr auto S21 = 5;
constexpr auto S22 = 9;
constexpr auto S23 = 14;
constexpr auto S24 = 20;
constexpr auto S31 = 4;
constexpr auto S32 = 11;
constexpr auto S33 = 16;
constexpr auto S34 = 23;
constexpr auto S41 = 6;
constexpr auto S42 = 10;
constexpr auto S43 = 15;
constexpr auto S44 = 21;

static const uint32_t T[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

uint32_t reverseByteOrder(uint32_t bytes)
{
	uint32_t aux = 0;
	uint8_t byte;
	int i;

	for (i = 0; i < 32; i += 8)
	{
		byte = (bytes >> i) & 0xff;
		aux |= byte << (32 - 8 - i);
	}
	return aux;
}

/* Rotate @c x left @c n bits*/
constexpr uint32_t rotateLeft(uint32_t x, uint32_t n)
{
	return (x << n) | (x) >> (32 - n);
}

struct MD5
{
public:
	std::string digest(const std::string& message)
	{
		if (m_buffer)
		{
			delete m_buffer;
		}

		assignWithPadding(message);
		process();

		std::stringstream hexdigest;
		hexdigest << std::setfill('0') << std::setw(8) << std::right << std::hex <<
			reverseByteOrder(m_context.a) << 
			reverseByteOrder(m_context.b) << 
			reverseByteOrder(m_context.c) << 
			reverseByteOrder(m_context.d);

		return hexdigest.str();
	}

	~MD5()
	{
		if (m_buffer)
		{
			delete m_buffer;
		}
	}

private:
	void assignWithPadding(const std::string& message)
	{
		const size_t lengthInBytes = message.size();
		const size_t lengthInBits = lengthInBytes * kBitsInByte;

		const size_t moduloDivision = lengthInBits % kPaddingBits;
		const size_t bitsToPad = (moduloDivision == kPaddingCongruentBits ? kPaddingBits :
			kPaddingCongruentBits > moduloDivision ? kPaddingCongruentBits - moduloDivision :
			kPaddingBits - (moduloDivision - kPaddingCongruentBits));
		const size_t bytesToPad = bitsToPad / kBitsInByte;

		// Currently the implementation does not support the message of size that is not measurable in the decimal amount of bytes
		assert(bitsToPad % kBitsInByte == 0 && "Non-byte structure.");

		// Multiple of 512 bits
		m_bufferLength = lengthInBytes + bytesToPad + kMessageLengthBits / kBitsInByte;
		m_buffer = new char[m_bufferLength];

		std::strncpy(m_buffer, message.c_str(), lengthInBytes);
		m_buffer[lengthInBytes] = kFirstPaddingByte;
		std::fill_n(m_buffer + lengthInBytes + 1, bytesToPad - 1, kPaddingByte);
		*reinterpret_cast<uint64_t*>(m_buffer + lengthInBytes + bytesToPad) = lengthInBits;
	}

	void process()
	{
		uint32_t* wordPointer = reinterpret_cast<uint32_t*>(m_buffer);
		for (size_t i = 0; i < m_bufferLength / (4 * 16); ++i)
		{
			std::array<uint32_t, 16> x;
			for (size_t j = 0; j < 16; ++j)
			{
				x[j] = wordPointer[j];
			}

			auto& [a, b, c, d] = m_context;
			auto [aa, bb, cc, dd] = m_context;

			/*
			 * k - kth word from the 16-element chunk
			 * s - shift
			 * i - ith from T-table
			 */
			auto consume = [&x, this](decltype(MD5::f) roundfunc, uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t xk, size_t s, size_t i)
			{
				/*a = b + rotateLeft(a + f(b, c, d) + xk + T[i], s);*/
				a += roundfunc(b, c, d) + xk + T[i];
				a = rotateLeft(a, s);
				a += b;
			};

			/* Round 1 */
			consume(&MD5::f, a, b, c, d, x[0], S11, 0); /* 1 */
			consume(&MD5::f, d, a, b, c, x[1], S12, 1); /* 2 */
			consume(&MD5::f, c, d, a, b, x[2], S13, 2); /* 3 */
			consume(&MD5::f, b, c, d, a, x[3], S14, 3); /* 4 */
			consume(&MD5::f, a, b, c, d, x[4], S11, 4); /* 5 */
			consume(&MD5::f, d, a, b, c, x[5], S12, 5); /* 6 */
			consume(&MD5::f, c, d, a, b, x[6], S13, 6); /* 7 */
			consume(&MD5::f, b, c, d, a, x[7], S14, 7); /* 8 */
			consume(&MD5::f, a, b, c, d, x[8], S11, 8); /* 9 */
			consume(&MD5::f, d, a, b, c, x[9], S12, 9); /* 10 */
			consume(&MD5::f, c, d, a, b, x[10], S13, 10); /* 11 */
			consume(&MD5::f, b, c, d, a, x[11], S14, 11); /* 12 */
			consume(&MD5::f, a, b, c, d, x[12], S11, 12); /* 13 */
			consume(&MD5::f, d, a, b, c, x[13], S12, 13); /* 14 */
			consume(&MD5::f, c, d, a, b, x[14], S13, 14); /* 15 */
			consume(&MD5::f, b, c, d, a, x[15], S14, 15); /* 16 */

			/* Round 2 */
			consume(&MD5::g, a, b, c, d, x[1], S21, 16); /* 17 */
			consume(&MD5::g, d, a, b, c, x[6], S22, 17); /* 18 */
			consume(&MD5::g, c, d, a, b, x[11], S23, 18); /* 19 */
			consume(&MD5::g, b, c, d, a, x[0], S24, 19); /* 20 */
			consume(&MD5::g, a, b, c, d, x[5], S21, 20); /* 21 */
			consume(&MD5::g, d, a, b, c, x[10], S22, 21); /* 22 */
			consume(&MD5::g, c, d, a, b, x[15], S23, 22); /* 23 */
			consume(&MD5::g, b, c, d, a, x[4], S24, 23); /* 24 */
			consume(&MD5::g, a, b, c, d, x[9], S21, 24); /* 25 */
			consume(&MD5::g, d, a, b, c, x[14], S22, 25); /* 26 */
			consume(&MD5::g, c, d, a, b, x[3], S23, 26); /* 27 */
			consume(&MD5::g, b, c, d, a, x[8], S24, 27); /* 28 */
			consume(&MD5::g, a, b, c, d, x[13], S21, 28); /* 29 */
			consume(&MD5::g, d, a, b, c, x[2], S22, 29); /* 30 */
			consume(&MD5::g, c, d, a, b, x[7], S23, 30); /* 31 */
			consume(&MD5::g, b, c, d, a, x[12], S24, 31); /* 32 */

			/* Round 3 */
			consume(&MD5::h, a, b, c, d, x[5], S31, 32); /* 33 */
			consume(&MD5::h, d, a, b, c, x[8], S32, 33); /* 34 */
			consume(&MD5::h, c, d, a, b, x[11], S33, 34); /* 35 */
			consume(&MD5::h, b, c, d, a, x[14], S34, 35); /* 36 */
			consume(&MD5::h, a, b, c, d, x[1], S31, 36); /* 37 */
			consume(&MD5::h, d, a, b, c, x[4], S32, 37); /* 38 */
			consume(&MD5::h, c, d, a, b, x[7], S33, 38); /* 39 */
			consume(&MD5::h, b, c, d, a, x[10], S34, 39); /* 40 */
			consume(&MD5::h, a, b, c, d, x[13], S31, 40); /* 41 */
			consume(&MD5::h, d, a, b, c, x[0], S32, 41); /* 42 */
			consume(&MD5::h, c, d, a, b, x[3], S33, 42); /* 43 */
			consume(&MD5::h, b, c, d, a, x[6], S34, 43); /* 44 */
			consume(&MD5::h, a, b, c, d, x[9], S31, 44); /* 45 */
			consume(&MD5::h, d, a, b, c, x[12], S32, 45); /* 46 */
			consume(&MD5::h, c, d, a, b, x[15], S33, 46); /* 47 */
			consume(&MD5::h, b, c, d, a, x[2], S34, 47); /* 48 */

			/* Round 4 */
			consume(&MD5::i, a, b, c, d, x[0], S41, 48); /* 49 */
			consume(&MD5::i, d, a, b, c, x[7], S42, 49); /* 50 */
			consume(&MD5::i, c, d, a, b, x[14], S43, 50); /* 51 */
			consume(&MD5::i, b, c, d, a, x[5], S44, 51); /* 52 */
			consume(&MD5::i, a, b, c, d, x[12], S41, 52); /* 53 */
			consume(&MD5::i, d, a, b, c, x[3], S42, 53); /* 54 */
			consume(&MD5::i, c, d, a, b, x[10], S43, 54); /* 55 */
			consume(&MD5::i, b, c, d, a, x[1], S44, 55); /* 56 */
			consume(&MD5::i, a, b, c, d, x[8], S41, 56); /* 57 */
			consume(&MD5::i, d, a, b, c, x[15], S42, 57); /* 58 */
			consume(&MD5::i, c, d, a, b, x[6], S43, 58); /* 59 */
			consume(&MD5::i, b, c, d, a, x[13], S44, 59); /* 60 */
			consume(&MD5::i, a, b, c, d, x[4], S41, 60); /* 61 */
			consume(&MD5::i, d, a, b, c, x[11], S42, 61); /* 62 */
			consume(&MD5::i, c, d, a, b, x[2], S43, 62); /* 63 */
			consume(&MD5::i, b, c, d, a, x[9], S44, 63); /* 64 */

			a += aa;
			b += bb;
			c += cc;
			d += dd;

			wordPointer += 16;
		}

	}

	/* RFC 1321 - 3.4 Step 4
	 * F(X,Y,Z) = XY v not(X) Z
     * G(X,Y,Z) = XZ v Y not(Z)
     * H(X,Y,Z) = X xor Y xor Z
     * I(X,Y,Z) = Y xor (X v not(Z))
	 */
	static constexpr uint32_t f(uint32_t x, uint32_t y, uint32_t z)
	{
		return (x & y) | (~x & z);
	}

	static constexpr uint32_t g(uint32_t x, uint32_t y, uint32_t z)
	{
		return (x & z) | (y & ~z);
	}

	static constexpr uint32_t h(uint32_t x, uint32_t y, uint32_t z)
	{
		return x ^ y ^ z;
	}

	static constexpr uint32_t i(uint32_t x, uint32_t y, uint32_t z)
	{
		return y ^ (x | ~z);
	}

private:
	char* m_buffer = nullptr;
	size_t m_bufferLength = 0;
	struct md5
	{
		uint32_t a;
		uint32_t b;
		uint32_t c;
		uint32_t d;
	} m_context = {s_wordA, s_wordB, s_wordC, s_wordD};

private:
	/* RFC 1321 - 3.3 Step 3 
	 * word A : 01 23 45 67
	 * word B : 89 ab cd ef
	 * word C : fe dc ba 98
	 * word D : 76 54 32 10
	 */
	static const uint32_t s_wordA = 0x67452301;
	static const uint32_t s_wordB = 0xefcdab89;
	static const uint32_t s_wordC = 0x98badcfe;
	static const uint32_t s_wordD = 0x10325476;
};

void runTests()
{
	std::vector<std::pair<std::string, std::string> > tests;
	tests.push_back(std::pair<std::string, std::string>("", "d41d8cd98f00b204e9800998ecf8427e"));
	tests.push_back(std::pair<std::string, std::string>("a", "0cc175b9c0f1b6a831c399e269772661"));
	tests.push_back(std::pair<std::string, std::string>("abc", "900150983cd24fb0d6963f7d28e17f72"));
	tests.push_back(std::pair<std::string, std::string>("message digest", "f96b697d7cb7938d525a2f31aaf161d0"));
	tests.push_back(std::pair<std::string, std::string>("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"));
	tests.push_back(std::pair<std::string, std::string>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"));
	tests.push_back(std::pair<std::string, std::string>("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a"));

	tests.push_back(std::pair<std::string, std::string>("This string is precisely 56 characters long for a reason", "93d268e9bef6608ff1a6a96adbeee106"));
	tests.push_back(std::pair<std::string, std::string>("This string is exactly 64 characters long for a very good reason", "655c37c2c8451a60306d09f2971e49ff"));
	tests.push_back(std::pair<std::string, std::string>("This string is also a specific length.  It is exactly 128 characters long for a very good reason as well. We are testing bounds.", "2ac62baa5be7fa36587c55691c026b35"));

	size_t failed = 0;
	for (auto&& test : tests)
	{
		MD5 md5;
		std::string digested = md5.digest(test.first);
		if (test.second != digested)
		{
			std::cerr << "FAILED: " << test.first << ", got `" << digested << "` but expected `" << test.second << "`." << std::endl;
			failed++;
		}
		else
		{
			std::cout << "SUCCESS: " << test.first << std::endl;
		}
	}

	if (!failed)
	{
		std::cout << "All tests passed!" << std::endl;
	}
}

std::string getFileSignature(const std::string& filepath)
{
	std::ifstream file(filepath);
	if (!file.is_open())
	{
		throw std::logic_error("Cannot open file: " + filepath);
	}

	std::string content((std::istreambuf_iterator<char>(file)),
		(std::istreambuf_iterator<char>()));
	MD5 md5;
	const std::string digested = md5.digest(content);

	file.close();

	return digested;
}

int main(int argc, const char *argv[])
{
	using namespace argparse;

	ArgumentParser parser(argv[0], "");
	parser.add_argument("--test", "Run tests");
	parser.add_argument("--file", "Generate hash for file.");
	parser.add_argument("--input", "Generate hash for file.");
	parser.add_argument("--verify", "Verify hash for file.");
	parser.enable_help();

	auto error = parser.parse(argc, argv);
	if (error) {
		std::cout << error << std::endl;
		return -1;
	}

	if (argc == 1)
	{
		parser.print_help();
		return -1;
	}

	const bool test = parser.exists("test");
	const bool file = parser.exists("file");
	const bool input = parser.exists("input");
	const bool verify = parser.exists("verify");

	if (test)
	{
		runTests();
	}
	else if (file)
	{
		const std::string filepath = parser.get<std::string>("file");
		try
		{
			const std::string signature = getFileSignature(filepath);
			std::cout << "File signature: " << signature << std::endl;
		}
		catch (const std::logic_error& e)
		{
			std::cerr << e.what() << std::endl;
			return -1;
		}
	}
	else if (input)
	{
		std::string input;
		std::cout << "Input content: ";
		std::cin >> input;

		MD5 md5;
		const std::string digested = md5.digest(input);
		std::cout << "Input signature: " << digested << std::endl;
	}
	else if (verify)
	{
		const std::string filepath = parser.get<std::string>("verify");
		try
		{
			const std::string signature = getFileSignature(filepath);
			std::string inputSignature;
			std::cout << "Your signature: ";
			std::cin >> inputSignature;

			if (inputSignature == signature)
			{
				std::cout << "File is OK." << std::endl;
			}
			else
			{
				std::cout << "File is not OK." << std::endl;
			}
		}
		catch (const std::logic_error& e)
		{
			std::cerr << e.what() << std::endl;
			return -1;
		}
	}

	return 0;
}
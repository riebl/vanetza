#include <gtest/gtest.h>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <memory>
#include <string>

using namespace vanetza::security;
using namespace vanetza;

class EccPointDecompressionVisitorTest: public ::testing::Test {
private:
	std::unique_ptr<BackendCryptoPP> backend_cryptopp;
	const std::string backend_name;
	std::unique_ptr<Backend> backend;

protected:
	EccPointDecompressionVisitorTest(std::string backend_name) :
			backend_name(backend_name) {
	}

	void SetUp() override {
		std::unique_ptr<Backend> backend_temp = create_backend("CryptoPP");
		backend_cryptopp = std::unique_ptr<BackendCryptoPP>(
				dynamic_cast<BackendCryptoPP*>(backend_temp.get()));
		backend_temp.release();
		ASSERT_TRUE(backend_cryptopp);

		backend = create_backend(backend_name);
		ASSERT_TRUE(backend);
	}

public:
	void test_decompression(const bool lsb_y) {
		Uncompressed point;
		// Re-generate a new random key until the LSB of the y coordinate matches
		do {
			ecdsa256::PublicKey pub = backend_cryptopp->generate_key_pair().public_key;
			point = {ByteBuffer(pub.x.begin(), pub.x.end()), ByteBuffer(pub.y.begin(), pub.y.end())};
		} while ((point.y.back() & 0x01) != lsb_y);

		EccPoint compressed;
		if (lsb_y) {
			compressed = Compressed_Lsb_Y_1 { point.x };
		} else {
			compressed = Compressed_Lsb_Y_0 { point.x };
		}
		Uncompressed decompressed(backend->decompress_ecc_point(compressed));

		EXPECT_EQ(point.y, decompressed.y);
	}
};

class EccPointDecompressionVisitorTestCryptoPP: public EccPointDecompressionVisitorTest {
public:
	EccPointDecompressionVisitorTestCryptoPP() :
			EccPointDecompressionVisitorTest("CryptoPP") {
	}
};

TEST_F(EccPointDecompressionVisitorTestCryptoPP, LSB_Y_0) {
	test_decompression(0);
}

TEST_F(EccPointDecompressionVisitorTestCryptoPP, LSB_Y_1) {
	test_decompression(1);
}

#ifdef VANETZA_WITH_OPENSSL
class EccPointDecompressionVisitorTestOpenSSL: public EccPointDecompressionVisitorTest {
public:
	EccPointDecompressionVisitorTestOpenSSL() :
			EccPointDecompressionVisitorTest("OpenSSL") {
	}
};

TEST_F(EccPointDecompressionVisitorTestOpenSSL, LSB_Y_0) {
	test_decompression(0);
}

TEST_F(EccPointDecompressionVisitorTestOpenSSL, LSB_Y_1) {
	test_decompression(1);
}
#endif


#include <vanetza/security/backend.hpp>
#include <gtest/gtest.h>
#include <algorithm>
#include <list>

#include "serialization.hpp"

using namespace vanetza;
using namespace vanetza::security;

class BackendTest : public ::testing::TestWithParam<std::string>
{
public:
    void SetUp() override
    {
        backend = create_backend(GetParam());
        ASSERT_NE(backend.get(), nullptr);
    }

    ByteBuffer buffer_from_string(const std::string& s)
    {
        ByteBuffer b;
        std::copy(s.begin(), s.end(), std::back_inserter(b));
        return b;
    }

    std::unique_ptr<Backend> backend;
};

TEST_P(BackendTest, sha256sum)
{
    const ByteBuffer input = buffer_from_string("All your ITS stations are belong to us");
    const ByteBuffer expected = buffer_from_hexstring("dcb61edffc5f536aeb80c7e61fc943239a28b16edad52f4a0bc6e83f2df0fdc8");
    EXPECT_EQ(backend->calculate_hash(KeyType::BrainpoolP256r1, input), expected);
}

TEST_P(BackendTest, sha384sum)
{
    const ByteBuffer input = buffer_from_string("All your ITS stations are belong to us");
    const ByteBuffer expected = buffer_from_hexstring("4dfdccefa8612f3285aa4e909c644eb841e0347132465a733cbc99b46437d9ea0886c96a25fd9d51389585431b069651");
    EXPECT_EQ(backend->calculate_hash(KeyType::BrainpoolP384r1, input), expected);
}

std::list<std::string> available_backends()
{
    std::list<std::string> backends;
    #ifdef VANETZA_WITH_OPENSSL
    backends.emplace_back("OpenSSL");
    #endif
    #ifdef VANETZA_WITH_CRYPTOPP
    backends.emplace_back("CryptoPP");
    #endif
    return backends;
}

INSTANTIATE_TEST_SUITE_P(BackendImplementations, BackendTest, ::testing::ValuesIn(available_backends()));

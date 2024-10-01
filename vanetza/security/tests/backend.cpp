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
    EXPECT_EQ(backend->calculate_hash(HashAlgorithm::SHA256, input), expected);
}

TEST_P(BackendTest, sha384sum)
{
    const ByteBuffer input = buffer_from_string("All your ITS stations are belong to us");
    const ByteBuffer expected = buffer_from_hexstring("4dfdccefa8612f3285aa4e909c644eb841e0347132465a733cbc99b46437d9ea0886c96a25fd9d51389585431b069651");
    EXPECT_EQ(backend->calculate_hash(HashAlgorithm::SHA384, input), expected);
}

TEST_P(BackendTest, sign_and_verify_nistp256)
{
    const ByteBuffer digest = buffer_from_hexstring("33e57499804cebc409407d6bf4ade70b49b58d0d4bae9ca57d507b260a676685");
    PrivateKey private_key;
    private_key.type = KeyType::NistP256;
    private_key.key = buffer_from_hexstring("f4ce0e4b48829aae85abd2124a2574dba44388eea94ebd373f9203ad39719a30");
    PublicKey public_key;
    public_key.type = KeyType::NistP256;
    public_key.compression = KeyCompression::NoCompression;
    public_key.x = buffer_from_hexstring("8e65e0ab7d4cd66860be693e29bf747fe796ebfe3942416b1f9c7ecf7fdb5797");
    public_key.y = buffer_from_hexstring("49ce27c4acfc53c34867420a35b999e7deb3aeabec388f0d08d7fe0edf54ba62");
    Signature sig = backend->sign_digest(private_key, digest);
    EXPECT_TRUE(backend->verify_digest(public_key, digest, sig));
}

TEST_P(BackendTest, sign_and_verify_brainpoolp256r1)
{
    const ByteBuffer digest = buffer_from_hexstring("33e57499804cebc409407d6bf4ade70b49b58d0d4bae9ca57d507b260a676685");
    PrivateKey private_key;
    private_key.type = KeyType::BrainpoolP256r1;
    private_key.key = buffer_from_hexstring("38f72493269d99c77b6e6488de05aea60bc707a35b464b0286665463ecc2883d");
    PublicKey public_key;
    public_key.type = KeyType::BrainpoolP256r1;
    public_key.compression = KeyCompression::NoCompression;
    public_key.x = buffer_from_hexstring("2cdb98f1053bb69fb4879101946d0a49aba965c8c4ffad5ef64356b0cff0bcf8");
    public_key.y = buffer_from_hexstring("17828cc0e33f68cbf9cb1d5419597464aef62efea8503676403177a9074cf86e");
    Signature sig = backend->sign_digest(private_key, digest);
    EXPECT_TRUE(backend->verify_digest(public_key, digest, sig));
}

TEST_P(BackendTest, sign_and_verify_brainpoolp384r1)
{
    const ByteBuffer digest = buffer_from_hexstring("33e57499804cebc409407d6bf4ade70b49b58d0d4bae9ca57d507b260a676685");
    PrivateKey private_key;
    private_key.type = KeyType::BrainpoolP384r1;
    private_key.key = buffer_from_hexstring("29267526c4511103f094f4d9ef1e8a57e2e6429642188939b756fe6738db49744363ea4081601e5acebe091d258bcedd");
    PublicKey public_key;
    public_key.type = KeyType::BrainpoolP384r1;
    public_key.compression = KeyCompression::NoCompression;
    public_key.x = buffer_from_hexstring("271dd92e47814e1f6b39c29488a80a720ae18153597380f41b2079cca4d92373b058850af280e920b10993bf925bdc4a");
    public_key.y = buffer_from_hexstring("388b971cb0ad878842de6825e5f1a6e359c1c4cddd65593781af6179fa743c21a056577de9cca2631e107edc28dc2ef7");
    Signature sig = backend->sign_digest(private_key, digest);
    EXPECT_TRUE(backend->verify_digest(public_key, digest, sig));
}

TEST_P(BackendTest, verify_nistp256)
{
    Signature sig;
    sig.type = KeyType::NistP256;
    sig.r = buffer_from_hexstring("de99edf601b3682d90e6458ab0e5588fcdef54d679852e38fc85e7e16ad02074");
    sig.s = buffer_from_hexstring("552962f3572898a05dd99b179124d6e1d1a672a3f407083b59a1fe2dc62e8161");

    PublicKey public_key;
    public_key.type = KeyType::NistP256;
    public_key.compression = KeyCompression::NoCompression;
    public_key.x = buffer_from_hexstring("8e65e0ab7d4cd66860be693e29bf747fe796ebfe3942416b1f9c7ecf7fdb5797");
    public_key.y = buffer_from_hexstring("49ce27c4acfc53c34867420a35b999e7deb3aeabec388f0d08d7fe0edf54ba62");

    ByteBuffer digest = buffer_from_hexstring("33e57499804cebc409407d6bf4ade70b49b58d0d4bae9ca57d507b260a676685");
    EXPECT_TRUE(backend->verify_digest(public_key, digest, sig));

    ByteBuffer false_digest = digest;
    false_digest[0] ^= 0x01;
    EXPECT_FALSE(backend->verify_digest(public_key, false_digest, sig));
}

TEST_P(BackendTest, verify_brainpoolp256r1)
{
    Signature sig;
    sig.type = KeyType::BrainpoolP256r1;
    sig.r = buffer_from_hexstring("28c9b30e37b05388c2f04be921dbc79480d972f1c782ff8c5ade76c40e136d5a");
    sig.s = buffer_from_hexstring("77cf1e91d0204d2a58847b543df055605ff968cd6120c4ac9c751be08d782518");

    PublicKey public_key;
    public_key.type = KeyType::BrainpoolP256r1;
    public_key.compression = KeyCompression::NoCompression;
    public_key.x = buffer_from_hexstring("2cdb98f1053bb69fb4879101946d0a49aba965c8c4ffad5ef64356b0cff0bcf8");
    public_key.y = buffer_from_hexstring("17828cc0e33f68cbf9cb1d5419597464aef62efea8503676403177a9074cf86e");

    ByteBuffer digest = buffer_from_hexstring("33e57499804cebc409407d6bf4ade70b49b58d0d4bae9ca57d507b260a676685");
    EXPECT_TRUE(backend->verify_digest(public_key, digest, sig));

    ByteBuffer false_digest = digest;
    false_digest[0] ^= 0x01;
    EXPECT_FALSE(backend->verify_digest(public_key, false_digest, sig));
}

TEST_P(BackendTest, verify_brainpoolp384r1)
{
    Signature sig;
    sig.type = KeyType::BrainpoolP384r1;
    sig.r = buffer_from_hexstring("2b51c205ac9598ff245cbed8df5c8f3e1d9d3c7d6901a08d45e790784457900a84c903167f5d6b124ee193881ff93950");
    sig.s = buffer_from_hexstring("81c06d7f5fdf4e825b3cd8545956e6b1b587be4dcc66ce3007ca8b6966f90bc94efc8d88c70b5bd3bd44739ec34da54f");

    PublicKey public_key;
    public_key.type = KeyType::BrainpoolP384r1;
    public_key.compression = KeyCompression::NoCompression;
    public_key.x = buffer_from_hexstring("271dd92e47814e1f6b39c29488a80a720ae18153597380f41b2079cca4d92373b058850af280e920b10993bf925bdc4a");
    public_key.y = buffer_from_hexstring("388b971cb0ad878842de6825e5f1a6e359c1c4cddd65593781af6179fa743c21a056577de9cca2631e107edc28dc2ef7");

    ByteBuffer digest = buffer_from_hexstring("33e57499804cebc409407d6bf4ade70b49b58d0d4bae9ca57d507b260a676685");
    EXPECT_TRUE(backend->verify_digest(public_key, digest, sig));

    ByteBuffer false_digest = digest;
    false_digest[0] ^= 0x01;
    EXPECT_FALSE(backend->verify_digest(public_key, false_digest, sig));
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

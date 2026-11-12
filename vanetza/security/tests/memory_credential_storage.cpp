#include <vanetza/security/memory_credential_storage.hpp>
#include <gtest/gtest.h>
#include <functional>
#include <set>
#include <stdexcept>
#include <string>

using vanetza::ByteBuffer;
using namespace vanetza::security;

namespace
{

PublicKey make_public_key(std::uint8_t x, KeyCompression compression)
{
    PublicKey key;
    key.type = KeyType::NistP256;
    key.compression = compression;
    key.x.assign(32, x);
    return key;
}

PrivateKey make_private_key(std::uint8_t scalar)
{
    return PrivateKey { KeyType::NistP256, ByteBuffer(32, scalar) };
}

class NameCollector : public CredentialVisitor
{
public:
    void visit(const std::string& name) override { names.insert(name); }

    std::set<std::string> names;
};

class ModifyingVisitor : public CredentialVisitor
{
public:
    explicit ModifyingVisitor(std::function<void()> modify) : m_modify(std::move(modify)) {}

    void visit(const std::string&) override { m_modify(); }

private:
    std::function<void()> m_modify;
};

} // namespace

class MemoryCredentialStorageTest : public ::testing::Test
{
protected:
    MemoryCredentialStorage storage;
    const PublicKey pub_a = make_public_key(0x11, KeyCompression::Y0);
    const PrivateKey priv_a = make_private_key(0xA1);
    const PublicKey pub_b = make_public_key(0x22, KeyCompression::Y1);
    const PrivateKey priv_b = make_private_key(0xB2);
};

TEST_F(MemoryCredentialStorageTest, fetches_stored_private_keys)
{
    storage.store(pub_a, priv_a);
    storage.store(pub_b, priv_b);

    boost::optional<PrivateKey> fetched_a = storage.fetch(pub_a);
    ASSERT_TRUE(fetched_a);
    EXPECT_EQ(priv_a.type, fetched_a->type);
    EXPECT_EQ(priv_a.key, fetched_a->key);

    boost::optional<PrivateKey> fetched_b = storage.fetch(pub_b);
    ASSERT_TRUE(fetched_b);
    EXPECT_EQ(priv_b.key, fetched_b->key);
}

TEST_F(MemoryCredentialStorageTest, fetch_of_unknown_key_is_none)
{
    storage.store(pub_a, priv_a);
    EXPECT_FALSE(storage.fetch(pub_b));
}

TEST_F(MemoryCredentialStorageTest, fetch_ignores_compression_form_of_public_key)
{
    PublicKey uncompressed = make_public_key(0x33, KeyCompression::NoCompression);
    uncompressed.y.assign(32, 0x44); // even y matches Y0
    storage.store(uncompressed, priv_a);

    boost::optional<PrivateKey> fetched = storage.fetch(make_public_key(0x33, KeyCompression::Y0));
    ASSERT_TRUE(fetched);
    EXPECT_EQ(priv_a.key, fetched->key);
}

TEST_F(MemoryCredentialStorageTest, store_ignores_malformed_public_key)
{
    PublicKey truncated = make_public_key(0x11, KeyCompression::Y0);
    truncated.x.pop_back();
    storage.store(truncated, priv_a);

    // malformed keys must not share a stored credential
    PublicKey uncompressed_without_y = make_public_key(0x22, KeyCompression::NoCompression);
    EXPECT_FALSE(storage.fetch(uncompressed_without_y));
}

TEST_F(MemoryCredentialStorageTest, discard_reports_whether_key_was_removed)
{
    storage.store(pub_a, priv_a);
    storage.store(pub_b, priv_b);

    EXPECT_TRUE(storage.discard(pub_a));
    EXPECT_FALSE(storage.fetch(pub_a));
    EXPECT_TRUE(storage.fetch(pub_b));
    EXPECT_FALSE(storage.discard(pub_a));
}

TEST_F(MemoryCredentialStorageTest, visit_yields_canonical_names_of_stored_keys)
{
    storage.store(pub_a, priv_a);
    storage.store(pub_b, priv_b);

    NameCollector collector;
    ASSERT_EQ(std::error_code(), storage.visit(collector));
    EXPECT_EQ((std::set<std::string> { canonical_hexstring(pub_a), canonical_hexstring(pub_b) }), collector.names);
}

TEST_F(MemoryCredentialStorageTest, modifying_while_visiting_is_logic_error)
{
    storage.store(pub_a, priv_a);

    ModifyingVisitor storing([this]() { storage.store(pub_b, priv_b); });
    EXPECT_THROW(storage.visit(storing), std::logic_error);

    ModifyingVisitor discarding([this]() { EXPECT_TRUE(storage.discard(pub_b)); });
    EXPECT_THROW(storage.visit(discarding), std::logic_error);

    storage.store(pub_b, priv_b);
    ModifyingVisitor discarding_by_name([this]() { EXPECT_TRUE(storage.discard(canonical_hexstring(pub_b)).value()); });
    EXPECT_THROW(storage.visit(discarding_by_name), std::logic_error);
}

TEST_F(MemoryCredentialStorageTest, discard_by_name_reports_whether_key_was_removed)
{
    storage.store(pub_a, priv_a);
    storage.store(pub_b, priv_b);

    EXPECT_TRUE(storage.discard(canonical_hexstring(pub_a)).value());
    EXPECT_FALSE(storage.fetch(pub_a));
    EXPECT_TRUE(storage.fetch(pub_b));
    EXPECT_FALSE(storage.discard(canonical_hexstring(pub_a)).value());
}

TEST_F(MemoryCredentialStorageTest, contains_names_of_stored_keys_only)
{
    storage.store(pub_a, priv_a);

    EXPECT_TRUE(storage.contains(canonical_hexstring(pub_a)).value());
    EXPECT_FALSE(storage.contains(canonical_hexstring(pub_b)).value());
}

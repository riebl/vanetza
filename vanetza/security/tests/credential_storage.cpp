#include <vanetza/security/credential_storage.hpp>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <system_error>

using namespace vanetza::security;

namespace
{

// implements only the operations every credential storage has to support
class MandatoryOnlyStorage : public CredentialStorage
{
public:
    void store(const PublicKey&, const PrivateKey&) override {}
    boost::optional<PrivateKey> fetch(const PublicKey&) override { return boost::none; }
    bool discard(const PublicKey&) override { return false; }
};

class CountingVisitor : public CredentialVisitor
{
public:
    void visit(const std::string&) override { ++count; }

    unsigned count = 0;
};

const std::string name = "030000000000000000000000000000000000000000000000000000000000000000";

// Fake storage for ScopedCredential tests: records store/discard calls and can throw on store.
class FakeStorage : public CredentialStorage
{
public:
    void store(const PublicKey&, const PrivateKey&) override
    {
        ++store_count;
        stored = true;
        if (throw_on_store) {
            throw std::runtime_error("store failed");
        }
    }

    boost::optional<PrivateKey> fetch(const PublicKey&) override
    {
        return boost::none;
    }

    bool discard(const PublicKey&) override
    {
        ++discard_count;
        stored = false;
        return true;
    }

    int store_count = 0;
    int discard_count = 0;
    bool stored = false;
    bool throw_on_store = false;
};

} // namespace

TEST(CredentialStorage, visit_is_unsupported_by_default)
{
    MandatoryOnlyStorage storage;
    CountingVisitor visitor;
    EXPECT_EQ(std::errc::operation_not_supported, storage.visit(visitor));
    EXPECT_EQ(0, visitor.count);
}

TEST(CredentialStorage, discard_by_name_is_unsupported_by_default)
{
    MandatoryOnlyStorage storage;
    // discard(const PublicKey&) of MandatoryOnlyStorage hides the inherited overload
    CredentialStorage& base = storage;
    vanetza::expected<bool> result = base.discard(name);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(std::errc::operation_not_supported, result.error());
}

TEST(CredentialStorage, contains_is_unsupported_by_default)
{
    MandatoryOnlyStorage storage;
    vanetza::expected<bool> result = storage.contains(name);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(std::errc::operation_not_supported, result.error());
}

TEST(ScopedCredential, normal_scope_exit_discards_once)
{
    FakeStorage storage;
    PublicKey pub;
    PrivateKey priv;
    {
        ScopedCredential scoped(storage, pub, priv);
        EXPECT_EQ(1, storage.store_count);
        EXPECT_TRUE(storage.stored);
        EXPECT_EQ(0, storage.discard_count);
    }
    EXPECT_EQ(1, storage.discard_count);
    EXPECT_FALSE(storage.stored);
}

TEST(ScopedCredential, commit_preserves_stored_credential)
{
    FakeStorage storage;
    PublicKey pub;
    PrivateKey priv;
    {
        ScopedCredential scoped(storage, pub, priv);
        scoped.commit();
        EXPECT_EQ(1, storage.store_count);
        EXPECT_TRUE(storage.stored);
        EXPECT_EQ(0, storage.discard_count);
    }
    EXPECT_EQ(0, storage.discard_count);
    EXPECT_TRUE(storage.stored);
}

TEST(ScopedCredential, throw_from_following_protocol_step_discards_once)
{
    FakeStorage storage;
    PublicKey pub;
    PrivateKey priv;
    EXPECT_THROW({
        ScopedCredential scoped(storage, pub, priv);
        EXPECT_EQ(1, storage.store_count);
        EXPECT_TRUE(storage.stored);
        throw std::runtime_error("protocol step failed");
    }, std::runtime_error);
    EXPECT_EQ(1, storage.discard_count);
    EXPECT_FALSE(storage.stored);
}

TEST(ScopedCredential, store_throw_discards_inserted_credential_once)
{
    FakeStorage storage;
    PublicKey pub;
    PrivateKey priv;
    storage.throw_on_store = true;
    EXPECT_THROW(ScopedCredential scoped(storage, pub, priv), std::runtime_error);
    EXPECT_EQ(1, storage.store_count);
    EXPECT_EQ(1, storage.discard_count);
    EXPECT_FALSE(storage.stored);
}

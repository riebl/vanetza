#include <vanetza/security/credential_storage.hpp>
#include <gtest/gtest.h>
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

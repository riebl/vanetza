#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/tests/null_crypto_provider.hpp>
#include <vanetza/security/v3/memory_authorization_ticket_pool.hpp>
#include <vanetza/security/v3/naive_certificate_provider.hpp>
#include <gtest/gtest.h>
#include <memory>
#include <vector>

using namespace vanetza;
using namespace vanetza::security;

namespace
{

class TicketCollector : public v3::AuthorizationTicketPool::Visitor
{
public:
    void visit(const HashedId8& id, const v3::Credential& ticket) override
    {
        ids.push_back(id);
        keys.push_back(ticket.key.data);
    }

    std::vector<HashedId8> ids;
    std::vector<ByteBuffer> keys;
};

class MemoryAuthorizationTicketPoolTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        if (!crypto) {
            GTEST_SKIP() << "no crypto provider built in";
        }
    }

    ManualRuntime runtime { Clock::at("2024-08-12 11:30") };
    v3::NaiveCertificateProvider certificates { runtime };
    std::unique_ptr<CryptoProvider> crypto = create_crypto_provider();
    v3::MemoryAuthorizationTicketPool pool { crypto ? *crypto : NullCryptoProvider::instance() };
    const KeyReference key { ByteBuffer { 0x01, 0x02, 0x03 } };
};

} // namespace

TEST_F(MemoryAuthorizationTicketPoolTest, added_ticket_is_visited_and_fetched)
{
    const v3::Certificate ticket = certificates.generate_authorization_ticket();
    const boost::optional<HashedId8> id = ticket.calculate_digest(*crypto);
    ASSERT_TRUE(id);
    EXPECT_TRUE(pool.add(v3::Credential { ticket, key }));

    TicketCollector collector;
    pool.visit(collector);
    EXPECT_EQ(std::vector<HashedId8> { *id }, collector.ids);
    EXPECT_EQ(std::vector<ByteBuffer> { key.data }, collector.keys);

    boost::optional<v3::Credential> fetched = pool.fetch(*id);
    ASSERT_TRUE(fetched);
    EXPECT_EQ(*id, fetched->certificate.calculate_digest(*crypto).value());
    EXPECT_EQ(key.data, fetched->key.data);
}

TEST_F(MemoryAuthorizationTicketPoolTest, added_again_ticket_replaces_key_reference)
{
    const v3::Certificate ticket = certificates.generate_authorization_ticket();
    const boost::optional<HashedId8> id = ticket.calculate_digest(*crypto);
    ASSERT_TRUE(id);
    const KeyReference other_key { ByteBuffer { 0x04, 0x05 } };
    ASSERT_TRUE(pool.add(v3::Credential { ticket, key }));
    EXPECT_TRUE(pool.add(v3::Credential { ticket, other_key }));

    TicketCollector collector;
    pool.visit(collector);
    EXPECT_EQ(std::vector<HashedId8> { *id }, collector.ids);
    boost::optional<v3::Credential> fetched = pool.fetch(*id);
    ASSERT_TRUE(fetched);
    EXPECT_EQ(other_key.data, fetched->key.data);
}

TEST_F(MemoryAuthorizationTicketPoolTest, removed_ticket_is_gone)
{
    const v3::Certificate ticket = certificates.generate_authorization_ticket();
    const boost::optional<HashedId8> id = ticket.calculate_digest(*crypto);
    ASSERT_TRUE(id);
    ASSERT_TRUE(pool.add(v3::Credential { ticket, key }));

    EXPECT_TRUE(pool.remove(*id));
    EXPECT_FALSE(pool.remove(*id));
    EXPECT_FALSE(pool.fetch(*id));
    TicketCollector collector;
    pool.visit(collector);
    EXPECT_TRUE(collector.ids.empty());
}

TEST_F(MemoryAuthorizationTicketPoolTest, ticket_without_digest_is_rejected)
{
    // certificate lacking a verification key has no digest identifying it
    EXPECT_FALSE(pool.add(v3::Credential { v3::Certificate {}, key }));
    TicketCollector collector;
    pool.visit(collector);
    EXPECT_TRUE(collector.ids.empty());
}

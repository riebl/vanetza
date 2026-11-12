#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/tests/null_crypto_provider.hpp>
#include <vanetza/security/v3/identity_manager.hpp>
#include <vanetza/security/v3/memory_authorization_ticket_pool.hpp>
#include <vanetza/security/v3/naive_certificate_provider.hpp>
#include <gtest/gtest.h>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

using namespace vanetza;
using namespace vanetza::security;

namespace
{

class RecordingSubscriber : public v3::IdentityManager::Subscriber
{
public:
    explicit RecordingSubscriber(bool approve = true) : m_approve(approve) {}

    bool prepare(const HashedId8& next) override
    {
        events.push_back("prepare");
        ids.push_back(next);
        if (on_prepare) {
            on_prepare();
        }
        return m_approve;
    }

    void commit(const HashedId8& next) override
    {
        events.push_back("commit");
        ids.push_back(next);
    }

    void abort() override
    {
        events.push_back("abort");
    }

    std::vector<std::string> events;
    std::vector<HashedId8> ids;
    std::function<void()> on_prepare;

private:
    bool m_approve;
};

class IdentityManagerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        if (!crypto) {
            GTEST_SKIP() << "no crypto provider built in";
        }
    }

    // adds a new authorization ticket to the pool
    HashedId8 add_ticket()
    {
        const v3::Certificate ticket = certificates.generate_authorization_ticket();
        EXPECT_TRUE(pool.add(v3::Credential { ticket, KeyReference {} }));
        return ticket.calculate_digest(*crypto).value();
    }

    // adds a ticket generated at given offset, i.e. its validity is shifted by that offset
    void add_ticket_shifted(Clock::duration offset)
    {
        const Clock::time_point now = runtime.now();
        runtime.reset(now + offset);
        add_ticket();
        runtime.reset(now);
    }

    // starts the identity manager with the tickets added so far
    void start()
    {
        identities = std::make_unique<v3::IdentityManager>(pool, runtime);
    }

    HashedId8 current_id() const
    {
        return identities->current_pseudonym()->certificate.calculate_digest(*crypto).value();
    }

    ManualRuntime runtime { Clock::at("2024-08-12 11:30") };
    v3::NaiveCertificateProvider certificates { runtime };
    std::unique_ptr<CryptoProvider> crypto = create_crypto_provider();
    v3::MemoryAuthorizationTicketPool pool { crypto ? *crypto : NullCryptoProvider::instance() };
    std::unique_ptr<v3::IdentityManager> identities;
};

} // namespace

TEST_F(IdentityManagerTest, pseudonym_is_selected_at_start)
{
    const HashedId8 ticket = add_ticket();
    start();
    ASSERT_NE(nullptr, identities->current_pseudonym());
    EXPECT_EQ(ticket, current_id());
}

TEST_F(IdentityManagerTest, only_tickets_valid_now_are_selected)
{
    add_ticket_shifted(-std::chrono::hours(24)); // expired
    add_ticket_shifted(std::chrono::hours(24)); // not yet valid
    start();
    EXPECT_EQ(nullptr, identities->current_pseudonym());

    const HashedId8 valid = add_ticket();
    EXPECT_TRUE(identities->change_pseudonym());
    EXPECT_EQ(valid, current_id());
    EXPECT_FALSE(identities->change_pseudonym());
}

TEST_F(IdentityManagerTest, current_pseudonym_signs_permitted_application)
{
    add_ticket();
    start();
    ASSERT_NE(nullptr, identities->current_pseudonym());
    EXPECT_EQ(identities->current_pseudonym(), identities->signing_credential(aid::DEN));
}

TEST_F(IdentityManagerTest, current_pseudonym_does_not_sign_unpermitted_application)
{
    add_ticket();
    start();
    // tickets of NaiveCertificateProvider do not permit CRL
    EXPECT_EQ(nullptr, identities->signing_credential(aid::CRL));
}

TEST_F(IdentityManagerTest, nothing_is_signed_without_pseudonym)
{
    start();
    EXPECT_EQ(nullptr, identities->signing_credential(aid::DEN));
}

TEST_F(IdentityManagerTest, first_ticket_added_later_is_selected_by_change)
{
    start();
    EXPECT_EQ(nullptr, identities->current_pseudonym());
    EXPECT_FALSE(identities->change_pseudonym());
    const HashedId8 ticket = add_ticket();
    EXPECT_TRUE(identities->change_pseudonym());
    ASSERT_NE(nullptr, identities->current_pseudonym());
    EXPECT_EQ(ticket, current_id());
}

TEST_F(IdentityManagerTest, tickets_are_selected_with_equal_probability)
{
    const HashedId8 tickets[] = { add_ticket(), add_ticket(), add_ticket() };
    std::map<HashedId8, unsigned> selections;
    for (unsigned i = 0; i < 3000; ++i) {
        start();
        ++selections[current_id()];
    }

    // 1000 selections expected per ticket, a deviation of 200 is beyond seven standard deviations
    for (const HashedId8& ticket : tickets) {
        EXPECT_NEAR(1000.0, selections[ticket], 200.0);
    }
}

TEST_F(IdentityManagerTest, change_uses_every_ticket_once_per_round)
{
    const std::set<HashedId8> tickets { add_ticket(), add_ticket(), add_ticket() };

    // selection is random, thus repeated starts reveal a ticket reused within the first round
    for (int start_count = 0; start_count < 10; ++start_count) {
        start();
        std::set<HashedId8> used { current_id() };
        for (std::size_t i = 1; i < tickets.size(); ++i) {
            ASSERT_TRUE(identities->change_pseudonym());
            used.insert(current_id());
        }
        EXPECT_EQ(tickets, used);
    }

    // next round starts without keeping the current pseudonym
    const HashedId8 last = current_id();
    ASSERT_TRUE(identities->change_pseudonym());
    EXPECT_NE(last, current_id());
}

TEST_F(IdentityManagerTest, next_round_uses_every_ticket_once_again)
{
    const std::set<HashedId8> tickets { add_ticket(), add_ticket(), add_ticket() };

    // selection is random, thus repeated starts reveal a ticket reused within the second round
    for (int start_count = 0; start_count < 10; ++start_count) {
        start();
        for (std::size_t i = 1; i < tickets.size(); ++i) {
            ASSERT_TRUE(identities->change_pseudonym());
        }
        std::set<HashedId8> used;
        for (std::size_t i = 0; i < tickets.size(); ++i) {
            ASSERT_TRUE(identities->change_pseudonym());
            used.insert(current_id());
        }
        EXPECT_EQ(tickets, used);
    }
}

TEST_F(IdentityManagerTest, change_requires_another_ticket)
{
    const HashedId8 ticket = add_ticket();
    start();
    EXPECT_FALSE(identities->change_pseudonym());
    EXPECT_EQ(ticket, current_id());
}

TEST_F(IdentityManagerTest, subscribers_prepare_and_commit_next_pseudonym)
{
    add_ticket();
    add_ticket();
    start();
    RecordingSubscriber subscriber;
    identities->subscribe(subscriber);
    ASSERT_TRUE(identities->change_pseudonym());
    EXPECT_EQ((std::vector<std::string> { "prepare", "commit" }), subscriber.events);
    EXPECT_EQ((std::vector<HashedId8> { current_id(), current_id() }), subscriber.ids);
}

TEST_F(IdentityManagerTest, veto_aborts_change)
{
    add_ticket();
    add_ticket();
    start();
    const HashedId8 initial = current_id();
    RecordingSubscriber approving;
    RecordingSubscriber vetoing { false };
    identities->subscribe(approving);
    identities->subscribe(vetoing);
    EXPECT_FALSE(identities->change_pseudonym());
    EXPECT_EQ(initial, current_id());
    EXPECT_EQ((std::vector<std::string> { "prepare", "abort" }), approving.events);
    EXPECT_EQ((std::vector<std::string> { "prepare", "abort" }), vetoing.events);
}

TEST_F(IdentityManagerTest, unsubscribed_subscriber_is_not_involved)
{
    add_ticket();
    add_ticket();
    start();
    RecordingSubscriber subscriber;
    identities->subscribe(subscriber);
    identities->unsubscribe(subscriber);
    ASSERT_TRUE(identities->change_pseudonym());
    EXPECT_TRUE(subscriber.events.empty());
}

TEST_F(IdentityManagerTest, subscriber_unsubscribing_during_change_receives_no_further_calls)
{
    add_ticket();
    add_ticket();
    start();
    RecordingSubscriber leaving;
    RecordingSubscriber staying;
    leaving.on_prepare = [&]() { identities->unsubscribe(leaving); };
    identities->subscribe(leaving);
    identities->subscribe(staying);
    ASSERT_TRUE(identities->change_pseudonym());
    EXPECT_EQ((std::vector<std::string> { "prepare" }), leaving.events);
    EXPECT_EQ((std::vector<std::string> { "prepare", "commit" }), staying.events);
}

TEST_F(IdentityManagerTest, unsubscribed_subscribers_are_skipped_by_vetoed_change)
{
    add_ticket();
    add_ticket();
    start();
    RecordingSubscriber leaving;
    RecordingSubscriber removing;
    RecordingSubscriber removed;
    RecordingSubscriber vetoing { false };
    leaving.on_prepare = [&]() { identities->unsubscribe(leaving); };
    removing.on_prepare = [&]() { identities->unsubscribe(removed); };
    identities->subscribe(leaving);
    identities->subscribe(removing);
    identities->subscribe(removed);
    identities->subscribe(vetoing);
    EXPECT_FALSE(identities->change_pseudonym());
    EXPECT_EQ((std::vector<std::string> { "prepare" }), leaving.events);
    EXPECT_EQ((std::vector<std::string> { "prepare", "abort" }), removing.events);
    EXPECT_TRUE(removed.events.empty());
    EXPECT_EQ((std::vector<std::string> { "prepare", "abort" }), vetoing.events);
}

TEST_F(IdentityManagerTest, subscriber_added_during_change_joins_next_change)
{
    add_ticket();
    add_ticket();
    start();
    RecordingSubscriber inviting;
    RecordingSubscriber joining;
    inviting.on_prepare = [&]() { identities->subscribe(joining); };
    identities->subscribe(inviting);
    ASSERT_TRUE(identities->change_pseudonym());
    EXPECT_TRUE(joining.events.empty());
    ASSERT_TRUE(identities->change_pseudonym());
    EXPECT_EQ((std::vector<std::string> { "prepare", "commit" }), joining.events);
}

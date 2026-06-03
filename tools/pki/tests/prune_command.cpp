#include "prune_command.hpp"
#include "certificate.hpp"
#include "certificate_filesystem_storage.hpp"
#include "hashed_id8.hpp"
#include "mock_credential_storage.hpp"
#include "openssl_security_module.hpp"
#include "stub_certificate.hpp"
#include "stub_station_configuration.hpp"
#include <vanetza/security/public_key.hpp>
#include <gtest/gtest.h>
#include <chrono>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

using vanetza::Clock;

namespace vanetza
{
namespace pki
{
namespace
{

PublicKey make_random_pubkey()
{
    // SecurityModule::create_key generates a fresh key pair, stores the
    // private half in credential storage, and returns the public half.
    // Tests derive the canonical hex from the returned public key so test data
    // stays self-consistent.
    static auto credentials = std::make_shared<MockCredentialStorage>();
    static OpenSslSecurityModule sm(credentials);
    return sm.create_key(KeyType::BrainpoolP256r1);
}

class PruneTestFixture : public ::testing::Test
{
protected:
    void SetUp() override
    {
        root = std::filesystem::temp_directory_path() / "pki_unit_test_prune";
        std::filesystem::remove_all(root);

        cfg.credentials = std::make_shared<MockCredentialStorage>();
        cfg.security = std::make_shared<OpenSslSecurityModule>(cfg.credentials);
        const auto certs_dir = root / "certs";
        cfg.root_ca = std::make_shared<CertificateFilesystemStorage>(cfg.security, certs_dir, ".rca");
        cfg.enrolment_credentials = std::make_shared<CertificateFilesystemStorage>(cfg.security, certs_dir, ".ec");
        cfg.tlm = std::make_shared<CertificateFilesystemStorage>(cfg.security, certs_dir, ".tlm");
        cfg.tickets = std::make_shared<CertificateFilesystemStorage>(cfg.security, certs_dir, ".at");
        cfg.station = std::make_shared<StubStationConfiguration>();
    }

    void TearDown() override
    {
        std::filesystem::remove_all(root);
    }

    // Typed accessor for the StubStationConfiguration held in cfg.station.
    StubStationConfiguration& station()
    {
        return static_cast<StubStationConfiguration&>(*cfg.station);
    }

    std::filesystem::path root;
    MainConfig cfg;
};

constexpr auto NOW = std::chrono::seconds(1'700'000'000);
Clock::time_point at_offset(std::chrono::seconds offset)
{
    return Clock::time_point(NOW + offset);
}

struct ExpiredRecord
{
    std::string label;
    HashedId8 id;
    std::string name;
    Clock::time_point expires_at;
    std::string pubkey_hex; // empty for skipped entries
    bool skipped;
};

class RecordingExpiredVisitor : public PruneExpiredVisitor
{
public:
    void on_deletable(CertificateStorage&, const std::string& label, const HashedId8& id, const Certificate& c,
        const std::string& pk) override
    {
        records.push_back({ label, id, c.get_name(), c.valid_until(), pk, false });
    }

    void on_skipped(const std::string& label, const HashedId8& id, const Certificate& c) override
    {
        records.push_back({ label, id, c.get_name(), c.valid_until(), {}, true });
    }

    void on_summary() override
    {
        ++summary_count;
    }

    std::vector<ExpiredRecord> records;
    std::size_t summary_count = 0;
};

class RecordingOrphansVisitor : public PruneOrphansVisitor
{
public:
    void on_orphan(const std::string& hex) override
    {
        orphans.push_back(hex);
    }

    void on_summary() override
    {
        ++summary_count;
    }

    std::vector<std::string> orphans;
    std::size_t summary_count = 0;
};

} // anonymous namespace

} // namespace pki
} // namespace vanetza

using namespace vanetza::pki;

TEST_F(PruneTestFixture, prune_expired_picks_certs_with_valid_until_in_past)
{
    PublicKey live = make_random_pubkey();
    PublicKey dead = make_random_pubkey();
    cfg.enrolment_credentials->store(build_stub_certificate(live, nullptr, at_offset(std::chrono::seconds(0)),
        std::chrono::hours(1)));
    cfg.enrolment_credentials->store(build_stub_certificate(dead, nullptr, at_offset(std::chrono::seconds(-86400)),
        std::chrono::hours(1)));

    RecordingExpiredVisitor v;
    prune_expired(cfg, Clock::time_point(NOW), false, v);

    ASSERT_EQ(1u, v.records.size());
    EXPECT_FALSE(v.records[0].skipped);
    EXPECT_EQ("EC", v.records[0].label);
    EXPECT_EQ(vanetza::security::canonical_hexstring(dead), v.records[0].pubkey_hex);
    EXPECT_EQ(1u, v.summary_count);
}

TEST_F(PruneTestFixture, prune_expired_distinguishes_store_labels)
{
    PublicKey expired_ec = make_random_pubkey();
    PublicKey expired_at = make_random_pubkey();
    cfg.enrolment_credentials->store(build_stub_certificate(expired_ec, nullptr,
        at_offset(std::chrono::seconds(-86400)), std::chrono::hours(1)));
    cfg.tickets->store(build_stub_certificate(expired_at, nullptr, at_offset(std::chrono::seconds(-86400)),
        std::chrono::hours(1)));

    RecordingExpiredVisitor v;
    prune_expired(cfg, Clock::time_point(NOW), false, v);

    ASSERT_EQ(2u, v.records.size());
    std::unordered_set<std::string> labels;
    for (const auto& r : v.records) {
        labels.insert(r.label);
    }
    EXPECT_EQ(2u, labels.size());
    EXPECT_TRUE(labels.count("EC"));
    EXPECT_TRUE(labels.count("AT"));
}

TEST_F(PruneTestFixture, prune_expired_skips_station_referenced_without_force)
{
    PublicKey ec_key = make_random_pubkey();
    auto ec = build_stub_certificate(ec_key, nullptr, at_offset(std::chrono::seconds(-86400)), std::chrono::hours(1));
    HashedId8 ec_id = ec.calculate_hashed_id8(*cfg.security);
    cfg.enrolment_credentials->store(ec);
    station().set_ec_identifier(ec_id);

    RecordingExpiredVisitor v;
    prune_expired(cfg, Clock::time_point(NOW), false, v);

    ASSERT_EQ(1u, v.records.size());
    EXPECT_TRUE(v.records[0].skipped);
    EXPECT_EQ(ec_id, v.records[0].id);
}

TEST_F(PruneTestFixture, prune_expired_force_removes_station_referenced)
{
    PublicKey ec_key = make_random_pubkey();
    auto ec = build_stub_certificate(ec_key, nullptr, at_offset(std::chrono::seconds(-86400)), std::chrono::hours(1));
    HashedId8 ec_id = ec.calculate_hashed_id8(*cfg.security);
    cfg.enrolment_credentials->store(ec);
    station().set_ec_identifier(ec_id);

    RecordingExpiredVisitor v;
    prune_expired(cfg, Clock::time_point(NOW), false, v); // without force: skipped

    ASSERT_EQ(1u, v.records.size());
    EXPECT_TRUE(v.records[0].skipped);

    RecordingExpiredVisitor v2;
    prune_expired(cfg, Clock::time_point(NOW), true, v2); // with force: deletable
    ASSERT_EQ(1u, v2.records.size());
    EXPECT_FALSE(v2.records[0].skipped);
    EXPECT_EQ(ec_id, v2.records[0].id);
}

TEST_F(PruneTestFixture, prune_expired_keeps_not_yet_valid_certs)
{
    PublicKey future = make_random_pubkey();
    cfg.enrolment_credentials->store(build_stub_certificate(future, nullptr, at_offset(std::chrono::seconds(86400)),
        std::chrono::hours(1)));

    RecordingExpiredVisitor v;
    prune_expired(cfg, Clock::time_point(NOW), false, v);

    EXPECT_TRUE(v.records.empty());
    EXPECT_EQ(1u, v.summary_count);
}

TEST_F(PruneTestFixture, prune_orphans_emits_only_unreferenced_credentials)
{
    PublicKey ec_key = make_random_pubkey();
    PublicKey orphan_key = make_random_pubkey();

    // EC cert references ec_key; orphan_key has no cert
    cfg.enrolment_credentials->store(build_stub_certificate(ec_key));
    // Both private keys are in credential storage
    cfg.credentials->store(ec_key, PrivateKey {});
    cfg.credentials->store(orphan_key, PrivateKey {});

    RecordingOrphansVisitor v;
    prune_orphans(cfg, v);

    ASSERT_EQ(1u, v.orphans.size());
    EXPECT_EQ(vanetza::security::canonical_hexstring(orphan_key), v.orphans[0]);
    EXPECT_EQ(1u, v.summary_count);
}

TEST_F(PruneTestFixture, prune_orphans_empty_when_all_referenced)
{
    PublicKey k = make_random_pubkey();
    cfg.enrolment_credentials->store(build_stub_certificate(k));
    cfg.credentials->store(k, PrivateKey {});

    RecordingOrphansVisitor v;
    prune_orphans(cfg, v);

    EXPECT_TRUE(v.orphans.empty());
    EXPECT_EQ(1u, v.summary_count);
}

TEST_F(PruneTestFixture, prune_orphans_handles_empty_stores)
{
    RecordingOrphansVisitor v;
    prune_orphans(cfg, v);

    EXPECT_TRUE(v.orphans.empty());
    EXPECT_EQ(1u, v.summary_count);
}

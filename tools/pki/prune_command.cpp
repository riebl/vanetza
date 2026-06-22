#include "prune_command.hpp"
#include "certificate.hpp"
#include "certificate_storage.hpp"
#include "certificate_trust_list.hpp"
#include "credential_storage.hpp"
#include "hashed_id8.hpp"
#include "security_module.hpp"
#include "station_config.hpp"
#include "time.hpp"
#include "trust_list_storage.hpp"
#include <vanetza/security/public_key.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <boost/range/algorithm_ext/push_back.hpp>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace vanetza
{
namespace pki
{

namespace
{

// Stream expired certs from one store to the visitor. Constant memory.
void scan_store_for_expired(CertificateStorage& store, const std::string& label, Clock::time_point now,
    const StationConfiguration& station, bool force, PruneExpiredVisitor& visitor)
{
    auto station_ec = station.get_ec_identifier();
    auto station_root_ca = station.get_root_ca();

    for (const auto& id : store.list()) {
        auto cert = store.fetch(id);
        if (!cert) {
            std::cerr << "warning: " << label << " " << hexstring(id) << " could not be decoded; ignoring for prune\n";
            continue;
        } else if (cert->valid_until() >= now) {
            continue;
        }

        const bool station_ref = (station_ec && *station_ec == id) || (station_root_ca && *station_root_ca == id);

        if (station_ref && !force) {
            visitor.on_skipped(label, id, *cert);
        } else {
            std::string pubkey_hex = security::canonical_hexstring(cert->get_public_key());
            visitor.on_deletable(store, label, id, *cert, pubkey_hex);
        }
    }
}

// Collect canonical-hex public keys from one store into the set.
void collect_pubkey_hexes_from_store(const CertificateStorage& store, const char* label,
    std::unordered_set<std::string>& out)
{
    for (const auto& id : store.list()) {
        auto cert = store.fetch(id);
        if (!cert) {
            std::cerr << "warning: " << label << " " << hexstring(id) << " could not be decoded; ignoring for prune\n";
            continue;
        }
        std::string hex = security::canonical_hexstring(cert->get_public_key());
        if (!hex.empty()) {
            out.insert(std::move(hex));
        }
    }
}

// Format a cert entry for printing in expired-related output.
std::string format_expired_entry(const std::string& label, const HashedId8& id, const Certificate& cert)
{
    std::ostringstream os;
    os.imbue(std::cout.getloc());
    os << "[" << label << "] " << hexstring(id);
    const std::string name = cert.get_name();
    if (!name.empty()) {
        os << " \"" << name << "\"";
    }
    os << "  expired " << Clock::at(cert.valid_until());
    return os.str();
}

class DryRunPrintExpiredVisitor : public PruneExpiredVisitor
{
public:
    explicit DryRunPrintExpiredVisitor(const CredentialStorage* credentials) : m_credentials(credentials)
    {
    }

    void on_deletable(CertificateStorage&, const std::string& label, const HashedId8& id, const Certificate& cert,
        const std::string& pubkey_hex) override
    {
        std::cout << "  " << format_expired_entry(label, id, cert) << "\n";
        if (m_credentials && m_credentials->contains(pubkey_hex)) {
            std::cout << "    + would discard credential " << pubkey_hex << "\n";
        }
        ++m_deletable;
    }

    void on_skipped(const std::string& label, const HashedId8& id, const Certificate& cert) override
    {
        std::cout << "  " << format_expired_entry(label, id, cert) << "  [station-referenced, skipped — use --force]\n";
        ++m_skipped;
    }

    void on_summary() override
    {
        std::cout << "Would prune " << m_deletable << " certificate(s)";
        if (m_skipped) {
            std::cout << "; " << m_skipped << " skipped";
        }
        std::cout << ".\n";
    }

private:
    const CredentialStorage* m_credentials;
    std::size_t m_deletable = 0;
    std::size_t m_skipped = 0;
};

class ApplyExpiredVisitor : public PruneExpiredVisitor
{
public:
    explicit ApplyExpiredVisitor(CredentialStorage* credentials) : m_credentials(credentials)
    {
    }

    void on_deletable(CertificateStorage& store, const std::string& label, const HashedId8& id, const Certificate&,
        const std::string& pubkey_hex) override
    {
        if (store.erase(id)) {
            std::cout << "Removed " << label << " " << hexstring(id) << "\n";
            ++m_removed;
            if (m_credentials && m_credentials->discard(pubkey_hex)) {
                std::cout << "Removed credential " << pubkey_hex << "\n";
                ++m_removed_creds;
            }
        } else {
            std::cerr << "warning: failed to erase " << label << " " << hexstring(id) << "\n";
        }
    }

    void on_skipped(const std::string& label, const HashedId8& id, const Certificate&) override
    {
        std::cout << "Skipped " << label << " " << hexstring(id)
                  << " — referenced by station config (--force to remove)\n";
    }

    void on_summary() override
    {
        std::cout << "Pruned " << m_removed << " certificate(s)";
        if (m_credentials) {
            std::cout << " and " << m_removed_creds << " credential(s)";
        }
        std::cout << ".\n";
    }

private:
    CredentialStorage* m_credentials;
    std::size_t m_removed = 0;
    std::size_t m_removed_creds = 0;
};

class DryRunPrintOrphansVisitor : public PruneOrphansVisitor
{
public:
    void on_orphan(const std::string& canonical_hex) override
    {
        std::cout << "  " << canonical_hex << "\n";
        ++m_count;
    }

    void on_keep(const std::string& canonical_hex) override
    {
        ++m_keep;
    }

    void on_summary() override
    {
        std::cout << "Would prune " << m_count << " orphan and keep " << m_keep << " credential(s).\n";
    }

private:
    std::size_t m_count = 0;
    std::size_t m_keep = 0;
};

class ApplyOrphansVisitor : public PruneOrphansVisitor
{
public:
    explicit ApplyOrphansVisitor(const MainConfig& cfg) : m_cfg(cfg)
    {
    }

    void on_orphan(const std::string& canonical_hex) override
    {
        if (m_cfg.credentials->discard(canonical_hex)) {
            std::cout << "Removed orphan credential " << canonical_hex << "\n";
            ++m_removed;
        } else {
            std::cerr << "warning: failed to discard orphan credential " << canonical_hex << "\n";
        }
    }

    void on_summary() override
    {
        std::cout << "Pruned " << m_removed << " orphan credential(s).\n";
    }

private:
    const MainConfig& m_cfg;
    std::size_t m_removed = 0;
};

// Collects the HashedId8 of every AA/EA certificate encountered while visiting RCA CTLs.
class IssuerCollector : public CtlVisitor
{
public:
    explicit IssuerCollector(SecurityModule& security) : m_security(security)
    {
    }

    void add_authorization_authority(const Vanetza_Security_AaEntry_t& entry) override
    {
        m_aa.insert(Certificate(entry.aaCertificate).calculate_hashed_id8(m_security));
    }

    void add_enrolment_authority(const Vanetza_Security_EaEntry_t& entry) override
    {
        m_ea.insert(Certificate(entry.eaCertificate).calculate_hashed_id8(m_security));
    }

    const std::set<HashedId8>& authorization_authorities() const { return m_aa; }
    const std::set<HashedId8>& enrolment_authorities() const { return m_ea; }

private:
    SecurityModule& m_security;
    std::set<HashedId8> m_aa;
    std::set<HashedId8> m_ea;
};

// Remove every cert in `store` whose HashedId8 is not in `keep`. Returns the number pruned.
std::size_t reconcile_issuer_store(CertificateStorage& store, const std::set<HashedId8>& keep, const char* label,
    bool dry_run)
{
    std::vector<HashedId8> ids;
    boost::push_back(ids, store.list());
    std::size_t count = 0;
    for (const auto& id : ids) {
        if (keep.find(id) != keep.end()) {
            continue;
        }
        if (dry_run) {
            std::cout << "  would remove " << label << " " << hexstring(id) << "\n";
            ++count;
        } else if (store.erase(id)) {
            std::cout << "Removed " << label << " " << hexstring(id) << "\n";
            ++count;
        } else {
            std::cerr << "warning: failed to erase " << label << " " << hexstring(id) << "\n";
        }
    }
    return count;
}

} // namespace

void prune_ctl(const MainConfig& cfg, bool dry_run)
{
    // Build the current set of trusted issuer certs from the CTLs stored per Root CA.
    IssuerCollector collector(*cfg.security);
    for (const auto& rca : cfg.root_ca->list()) {
        auto ctl = cfg.trust_lists->fetch(rca);
        if (!ctl) {
            continue;
        }
        try {
            ctl->visit_rca_ctl(collector);
        } catch (const std::exception& e) {
            std::cerr << "warning: CTL for " << hexstring(rca) << " could not be parsed: " << e.what() << "\n";
        }
    }

    std::size_t count = 0;
    count += reconcile_issuer_store(*cfg.authorization_authorities, collector.authorization_authorities(), "AA", dry_run);
    count += reconcile_issuer_store(*cfg.enrolment_authorities, collector.enrolment_authorities(), "EA", dry_run);
    std::cout << (dry_run ? "Would prune " : "Pruned ") << count << " issuer certificate(s).\n";
}

void prune_expired(const MainConfig& cfg, Clock::time_point now, bool force, PruneExpiredVisitor& visitor)
{
    scan_store_for_expired(*cfg.root_ca, "Root CA", now, *cfg.station, force, visitor);
    scan_store_for_expired(*cfg.enrolment_credentials, "EC", now, *cfg.station, force, visitor);
    scan_store_for_expired(*cfg.tlm, "TLM", now, *cfg.station, force, visitor);
    scan_store_for_expired(*cfg.tickets, "AT", now, *cfg.station, force, visitor);
    visitor.on_summary();
}

void prune_expired_tickets(const MainConfig& cfg, Clock::time_point now, bool dry_run)
{
    CredentialStorage* credentials = cfg.credentials.get();
    if (dry_run) {
        std::cout << "Expired authorization tickets:\n";
        DryRunPrintExpiredVisitor visitor(credentials);
        scan_store_for_expired(*cfg.tickets, "AT", now, *cfg.station, true, visitor);
        visitor.on_summary();
    } else {
        ApplyExpiredVisitor visitor(credentials);
        scan_store_for_expired(*cfg.tickets, "AT", now, *cfg.station, true, visitor);
        visitor.on_summary();
    }
}

void prune_orphans(const MainConfig& cfg, PruneOrphansVisitor& visitor)
{
    std::unordered_set<std::string> referenced;
    collect_pubkey_hexes_from_store(*cfg.enrolment_credentials, "EC", referenced);
    collect_pubkey_hexes_from_store(*cfg.tickets, "AT", referenced);

    for (const auto& name : cfg.credentials->list()) {
        if (referenced.find(name) == referenced.end()) {
            visitor.on_orphan(name);
        } else {
            visitor.on_keep(name);
        }
    }
    visitor.on_summary();
}

std::shared_ptr<CLI::App> build_prune_command(const MainConfig& cfg)
{
    auto app = std::make_shared<CLI::App>("housekeeping for stored credentials and certificates", "prune");

    auto orphans = app->add_subcommand("orphans", "remove credential files not referenced by any certificate");
    auto orphans_dry = orphans->add_flag("--dry-run,-n", "list only; do not delete");
    orphans->callback([&cfg, orphans_dry]() {
        if (orphans_dry->as<bool>()) {
            std::cout << "Orphan credentials:\n";
            DryRunPrintOrphansVisitor v;
            prune_orphans(cfg, v);
        } else {
            ApplyOrphansVisitor v(cfg);
            prune_orphans(cfg, v);
        }
    });

    auto expired = app->add_subcommand("expired", "remove expired certificates");
    auto expired_dry = expired->add_flag("--dry-run,-n", "list only; do not delete");
    auto expired_force = expired->add_flag("--force", "also remove certs referenced by station config (EC, Root CA)");
    auto expired_keep =
        expired->add_flag("--keep-credentials", "keep corresponding credential when removing certificate");
    expired->callback([&cfg, expired_dry, expired_force, expired_keep]() {
        // Null pointer signals "do not touch credentials" (--keep-credentials).
        CredentialStorage* credentials = expired_keep->as<bool>() ? nullptr : cfg.credentials.get();
        const bool force = expired_force->as<bool>();
        if (expired_dry->as<bool>()) {
            std::cout << "Expired certificates:\n";
            DryRunPrintExpiredVisitor v(credentials);
            prune_expired(cfg, current_time(), force, v);
        } else {
            ApplyExpiredVisitor v(credentials);
            prune_expired(cfg, current_time(), force, v);
        }
    });

    auto ctl = app->add_subcommand("ctl", "remove exported AA/EA issuer certs no longer present in stored CTLs");
    auto ctl_dry = ctl->add_flag("--dry-run,-n", "list only; do not delete");
    ctl->callback([&cfg, ctl_dry]() {
        if (ctl_dry->as<bool>()) {
            std::cout << "Stale issuer certificates:\n";
        }
        prune_ctl(cfg, ctl_dry->as<bool>());
    });

    app->require_subcommand(1);
    return app;
}

} // namespace pki
} // namespace vanetza

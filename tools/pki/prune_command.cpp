#include "prune_command.hpp"
#include "certificate.hpp"
#include "certificate_storage.hpp"
#include "credential_storage.hpp"
#include "hashed_id8.hpp"
#include "station_config.hpp"
#include "time.hpp"
#include <vanetza/security/public_key.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_set>

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

} // namespace

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

    app->require_subcommand(1);
    return app;
}

} // namespace pki
} // namespace vanetza

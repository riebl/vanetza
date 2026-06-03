#pragma once

#include "certificate.hpp"
#include "certificate_storage.hpp"
#include "hashed_id8.hpp"
#include "main.hpp"
#include <vanetza/common/clock.hpp>
#include <CLI/CLI.hpp>
#include <memory>
#include <string>

namespace vanetza
{
namespace pki
{

/**
 * Visitor that observes expired certificates streamed by `prune_expired`.
 * Methods are called once per certificate as it is encountered. The driver
 * performs no per-cert buffering.
 */
class PruneExpiredVisitor
{
public:
    virtual ~PruneExpiredVisitor() = default;

    /**
     * An expired certificate eligible for deletion.
     *
     * \param store      backing store holding the cert; the visitor erases from it if needed
     * \param label      short role tag ("Root CA", "EC", "AT", "TLM") for output
     * \param pubkey_hex canonical-hex name of the corresponding credential
     */
    virtual void on_deletable(CertificateStorage& store, const std::string& label, const HashedId8&, const Certificate&,
        const std::string& pubkey_hex)
    {
    }

    /**
     * An expired certificate that is being skipped because it is referenced
     * by station configuration and `--force` was not specified.
     */
    virtual void on_skipped(const std::string& label, const HashedId8&, const Certificate&)
    {
    }

    /// Called once after all stores have been fully iterated.
    virtual void on_summary()
    {
    }
};

/**
 * Stream every expired certificate in the cert and ticket stores through the
 * visitor. Memory is constant — no per-cert state is retained.
 *
 * \param now   cutoff for expiry: `cert.valid_until() < now` ⇒ expired
 * \param force if true, station-referenced certs go to `on_deletable` instead
 *              of `on_skipped`
 */
void prune_expired(const MainConfig& cfg, Clock::time_point now, bool force, PruneExpiredVisitor& visitor);

/**
 * Prune expired authorization tickets and their credentials.
 * `dry_run` lists without deleting.
 */
void prune_expired_tickets(const MainConfig& cfg, Clock::time_point now, bool dry_run);

/// Visitor for `prune_orphans`. Same streaming pattern.
class PruneOrphansVisitor
{
public:
    virtual ~PruneOrphansVisitor() = default;

    /// An orphan credential eligible for deletion, by canonical-hex name.
    virtual void on_orphan(const std::string& canonical_hex)
    {
    }

    /// A credential retained because a certificate still references it.
    virtual void on_keep(const std::string& canonical_hex)
    {
    }

    /// Called once after all credentials have been iterated.
    virtual void on_summary()
    {
    }
};

/**
 * Stream every orphan credential through the visitor.
 * A credential is orphan when its canonical-hex name does not match any public key
 * referenced by a certificate in either store.
 */
void prune_orphans(const MainConfig& cfg, PruneOrphansVisitor& visitor);

// CLI subcommand tree.
std::shared_ptr<CLI::App> build_prune_command(const MainConfig&);

} // namespace pki
} // namespace vanetza

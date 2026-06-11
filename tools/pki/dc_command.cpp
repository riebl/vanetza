#include "dc_command.hpp"
#include "certificate_trust_list.hpp"
#include "distribution_centre.hpp"
#include "exception.hpp"
#include "hashed_id8_validator.hpp"
#include "validation.hpp"
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <functional>

namespace vanetza
{
namespace pki
{

namespace
{

const HashedId8Validator hid8_validator;

struct Context
{
    Context(const MainConfig& c) : cfg(c)
    {
    }

    void lookup_root_ca(CLI::Option* hid8_opt)
    {
        if (hid8_opt->count() == 0) {
            auto root_ca = cfg.station->get_root_ca();
            if (!root_ca) {
                throw UsageError("hid8 is required (station has no Root CA configured)");
            }
            hid8 = *root_ca;
        }
    }

    const std::string& url() const
    {
        return url_override.empty() ? cfg.dc_url : url_override;
    }

    const MainConfig& cfg;
    HashedId8 hid8;
    std::string url_override;
    bool print = false;
    std::function<void()> action;
};

void show_info(Context& ctx)
{
    std::cout << "DC URL: " << (ctx.url().empty() ? "[not set]" : ctx.url()) << "\n";
}

void fetch_ctl(Context& ctx, CLI::Option* hid8_opt, CLI::Option* dry_flag)
{
    ctx.lookup_root_ca(hid8_opt);
    DistributionCentre dc;
    dc.set_url(ctx.url());
    auto ctl = dc.fetch_trust_list(ctx.hid8);
    if (ctl) {
        if (ctx.print) {
            CtlListingVisitor visitor(*ctx.cfg.security);
            ctl->visit_rca_ctl(visitor);
        }

        auto ctl_digest = ctl->get_hashed_id8(*ctx.cfg.security);
        if (ctl_digest == ctx.hid8) {
            std::cout << "Fetched CTL matches Root CA digest\n";
        } else if (ctl_digest) {
            std::cout << "Fetched CTL has " << hexstring(*ctl_digest) << " digest mismatch.\n";
        } else {
            std::cout << "Cannot determine digest of CTL.\n";
        }

        if (auto cert = ctx.cfg.root_ca->fetch(ctx.hid8)) {
            bool valid = validate(*ctx.cfg.security, ctl->raw(), *cert);
            if (valid) {
                if (dry_flag->as<bool>()) {
                    std::cout << "CTL is valid. Storage unchanged in this dry run.\n";
                } else {
                    ctx.cfg.trust_lists->store(*ctl);
                    std::cout << "CTL is valid. Added to local trust list storage.\n";
                    // Materialize the AA/EA certs embedded in the validated CTL
                    CertificateExportVisitor exporter(ctx.cfg.authorization_authorities, ctx.cfg.enrolment_authorities);
                    ctl->visit_rca_ctl(exporter);
                    std::cout << "Exported " << exporter.exported_aa_certificates() << " AA and "
                        << exporter.exported_ea_certificates() << " EA certificate(s).\n";
                }
            } else {
                std::cout << "CTL cannot be trusted.\n";
            }
        } else {
            std::cout << "Cannot validate CTL because of missing Root CA certificate.\n";
        }
    } else {
        throw std::runtime_error("DC has no trust list matching HashedId8 " + hexstring(ctx.hid8));
    }
}

void fetch_crl(Context& ctx, CLI::Option* hid8_opt, CLI::Option* dry_flag)
{
    ctx.lookup_root_ca(hid8_opt);
    DistributionCentre dc;
    dc.set_url(ctx.url());
    auto crl = dc.fetch_revocation_list(ctx.hid8);
    if (!crl) {
        throw std::runtime_error("DC has no revocation list matching HashedId8 " + hexstring(ctx.hid8));
    }

    auto crl_digest = crl->get_hashed_id8(*ctx.cfg.security);
    if (crl_digest == ctx.hid8) {
        std::cout << "Fetched CRL matches Root CA digest\n";
    } else if (crl_digest) {
        std::cout << "Fetched CRL has " << hexstring(*crl_digest) << " digest mismatch.\n";
    } else {
        std::cout << "Cannot determine digest of CRL.\n";
    }

    if (ctx.print) {
        if (crl_digest) {
            std::cout << "Issuer: " << hexstring(*crl_digest) << "\n";
        }
        if (auto entries = crl->revoked_entries()) {
            std::cout << "Revoked certificates (" << entries->size() << "):\n";
            for (const auto& id : *entries) {
                std::cout << "- " << hexstring(id) << "\n";
            }
        } else {
            std::cout << "Revoked entries could not be decoded.\n";
        }
    }

    auto root_cert = ctx.cfg.root_ca->fetch(ctx.hid8);
    if (!root_cert) {
        std::cout << "Cannot validate CRL because of missing Root CA certificate.\n";
        return;
    }
    if (!validate(*ctx.cfg.security, crl->raw(), *root_cert)) {
        std::cout << "CRL cannot be trusted.\n";
        return;
    }

    if (dry_flag->as<bool>()) {
        std::cout << "CRL is valid. Storage unchanged in this dry run.\n";
    } else if (ctx.cfg.crl_store->store(*crl)) {
        std::cout << "CRL is valid. Added to local revocation list storage.\n";
    } else {
        std::cout << "CRL is valid but could not be indexed.\n";
    }
}

std::shared_ptr<CLI::App> build_info_command(std::shared_ptr<Context> ctx)
{
    auto app = std::make_shared<CLI::App>("Distribution Centre info", "info");
    app->callback([ctx]() { ctx->action = [ctx]() { show_info(*ctx); }; });
    app->fallthrough();
    return app;
}

std::shared_ptr<CLI::App> build_ctl_command(std::shared_ptr<Context> ctx)
{
    auto app = std::make_shared<CLI::App>("fetch certificate trust list (CTL)", "ctl");
    app->alias("getctl");

    auto hid8_opt = app->add_option("hid8", ctx->hid8, "HashedId8 of issuing entity (defaults to station's Root CA)")
                        ->check(hid8_validator);
    auto dry_flag = app->add_flag("--dry-run,-n", "fetch and validate only; do not store the CTL");

    app->callback([ctx, hid8_opt, dry_flag]() {
        ctx->action = [ctx, hid8_opt, dry_flag]() { fetch_ctl(*ctx, hid8_opt, dry_flag); };
    });

    app->fallthrough();
    return app;
}

std::shared_ptr<CLI::App> build_crl_command(std::shared_ptr<Context> ctx)
{
    auto app = std::make_shared<CLI::App>("fetch certificate revocation list (CRL)", "crl");
    app->alias("getcrl");

    auto hid8_opt = app->add_option("hid8", ctx->hid8, "HashedId8 of issuing Root CA (defaults to station's Root CA)")
                        ->check(hid8_validator);
    auto dry_flag = app->add_flag("--dry-run,-n", "fetch and validate only; do not store the CRL");

    app->callback([ctx, hid8_opt, dry_flag]() {
        ctx->action = [ctx, hid8_opt, dry_flag]() { fetch_crl(*ctx, hid8_opt, dry_flag); };
    });

    app->fallthrough();
    return app;
}

} // namespace

std::shared_ptr<CLI::App> build_dc_command(const MainConfig& cfg)
{
    auto ctx = std::make_shared<Context>(cfg);
    auto app = std::make_shared<CLI::App>("PKI Distribution Centre", "dc");
    app->add_flag("--print", ctx->print, "print received data in addition");
    app->add_option("--url", ctx->url_override, "override the Distribution Centre URL");

    app->add_subcommand(build_info_command(ctx));
    app->add_subcommand(build_ctl_command(ctx));
    app->add_subcommand(build_crl_command(ctx));

    app->require_subcommand(0, 1);
    app->final_callback([ctx]() {
        if (!ctx->action) {
            ctx->action = [ctx]() { show_info(*ctx); };
        }
        ctx->action();
    });
    return app;
}

} // namespace pki
} // namespace vanetza

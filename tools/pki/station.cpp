#include "station.hpp"
#include "certificate.hpp"
#include "hashed_id8.hpp"
#include "hashed_id8_validator.hpp"
#include <functional>
#include <iostream>

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

    const MainConfig& cfg;
    std::function<void()> action;
    std::string canonical;
    HashedId8 root_ca;
};

void print_station_summary(Context& ctx)
{
    const std::string canonical = ctx.cfg.station->get_canonical_identifier();
    const boost::optional<HashedId8> ec_id = ctx.cfg.station->get_ec_identifier();
    const boost::optional<HashedId8> root_ca = ctx.cfg.station->get_root_ca();

    std::cout << "Canonical identifier: " << (canonical.empty() ? "[unknown]" : canonical) << "\n";
    std::cout << "Enrolled: " << (ec_id ? "yes" : "no") << "\n";
    if (ec_id) {
        std::cout << "EC digest: " << hexstring(*ec_id) << "\n";
        boost::optional<Certificate> ec_cert = ctx.cfg.enrolment_credentials->fetch(*ec_id);
        std::cout << "EC certificate: " << (ec_cert ? "[available]" : "[missing]") << "\n";
    }

    if (root_ca) {
        std::cout << "Root CA: " << hexstring(*root_ca) << "\n";
        boost::optional<std::string> dc_url = lookup_dc_url(ctx.cfg.data_path / "ectl.ctl", *root_ca);
        if (dc_url) {
            std::cout << "DC URL: " << *dc_url << "\n";
        } else {
            std::cout << "DC URL: [not found in ECTL]\n";
        }
    } else {
        std::cout << "Root CA: [not set]\n";
    }
}

void set_root_ca(Context& ctx)
{
    if (auto cert = ctx.cfg.root_ca->fetch(ctx.root_ca)) {
        if (is_root_ca(*cert)) {
            ctx.cfg.station->set_root_ca(ctx.root_ca);
            std::cout << "Found Root CA certificate in cache.\n";
        } else {
            std::cout << "Found certificate matching " << hexstring(ctx.root_ca)
                      << ", but it is not a Root CA certificate!\n";
        }
    } else {
        std::cout << "Cannot set Root CA because the full certificate is missing.\n";
    }
}

} // namespace

std::shared_ptr<CLI::App> build_station_command(const MainConfig& cfg)
{
    auto ctx = std::make_shared<Context>(cfg);
    auto app = std::make_shared<CLI::App>("summary of station configuration", "station");

    auto set_canonical = app->add_subcommand("set-canonical-id", "set the canonical identifier");
    set_canonical->add_option("id", ctx->canonical, "canonical identifier")->required();
    set_canonical->callback([ctx]() {
        ctx->action = [ctx]() { ctx->cfg.station->set_canonical_identifier(ctx->canonical); };
    });

    auto set_root = app->add_subcommand("set-root-ca", "set the station's Root CA");
    set_root->add_option("hid8", ctx->root_ca, "HashedId8 of the Root CA")->required()->check(hid8_validator);
    set_root->callback([ctx]() { ctx->action = [ctx]() { set_root_ca(*ctx); }; });

    app->require_subcommand(0, 1);
    app->final_callback([ctx]() {
        if (!ctx->action) {
            ctx->action = [ctx]() { print_station_summary(*ctx); };
        }
        ctx->action();
    });

    return app;
}

} // namespace pki
} // namespace vanetza

#include "authorization.hpp"
#include "asn1.hpp"
#include "at_request.hpp"
#include "at_response.hpp"
#include "certificate.hpp"
#include "certificate_trust_list.hpp"
#include "ea_request.hpp"
#include "encrypted_data.hpp"
#include "exception.hpp"
#include "hexstring.hpp"
#include "http.hpp"
#include "prune_command.hpp"
#include "psid_ssp.hpp"
#include "response_codes.hpp"
#include "time.hpp"
#include "validation.hpp"
#include <vanetza/common/its_aid.hpp>
#include <CLI/CLI.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <chrono>
#include <iostream>
#include <list>
#include <map>
#include <stdexcept>

namespace vanetza
{
namespace pki
{

namespace
{

struct Context
{
    Context(const MainConfig& c) : cfg(c)
    {
    }

    std::string url(const AuthorizationAuthority& aa) const
    {
        return resolve_url(aa.access_point, url_override);
    }

    const MainConfig& cfg;
    std::string url_override;
    std::function<void()> action;

    KeyType key_type = KeyType::BrainpoolP256r1;
    HashAlgorithm hash_algo = HashAlgorithm::SHA256;
    std::list<PsidSsp> permissions;
    unsigned count = 1;
    Clock::time_point validity_start = current_time();
    std::chrono::hours validity_duration { 24 * 7 }; // 1 week, the CP §7.2.1 max
    bool custom_validity = false; // true if user set --validity-start/-duration; else no hint, AA picks
};

const std::map<std::string, KeyType> key_type_map = {
    { "NistP256", KeyType::NistP256 },
    { "BrainpoolP256r1", KeyType::BrainpoolP256r1 },
    { "BrainpoolP384r1", KeyType::BrainpoolP384r1 },
};

const std::map<std::string, HashAlgorithm> hash_algo_map = {
    { "SHA256", HashAlgorithm::SHA256 },
    { "SHA384", HashAlgorithm::SHA384 },
};

void list_tickets(Context& ctx);
void request_ticket(Context& ctx);

} // namespace

std::shared_ptr<CLI::App> build_authorization_command(const MainConfig& cfg)
{
    auto ctx = std::make_shared<Context>(cfg);
    auto app = std::make_shared<CLI::App>("authorization tickets (AT)", "authorization");
    app->alias("auth");
    app->alias("at");
    app->add_option("--url", ctx->url_override, "override the Authorization Authority URL");

    auto list = app->add_subcommand("list", "list stored authorization tickets");
    list->callback([ctx]() { ctx->action = [ctx]() { list_tickets(*ctx); }; });

    auto request = app->add_subcommand("request", "request a new authorization ticket");
    request->fallthrough();
    request->add_option("--key-type", ctx->key_type, "type of generated verification key")
        ->default_val(KeyType::BrainpoolP256r1)
        ->capture_default_str()
        ->transform(CLI::CheckedTransformer(key_type_map, CLI::ignore_case));
    request->add_option("--hash-algorithm", ctx->hash_algo, "hash algorithm for signing")
        ->default_val(HashAlgorithm::SHA256)
        ->capture_default_str()
        ->transform(CLI::CheckedTransformer(hash_algo_map, CLI::ignore_case));
    request->add_option("--permission", ctx->permissions, "requested AT permission (PSID[:HEX_SSP]); repeatable")
        ->required();
    request->add_option("--count", ctx->count, "number of ATs to request in this run")
        ->default_val(1)
        ->capture_default_str()
        ->check(CLI::PositiveNumber);
    CLI::callback_t validity_start_cb = [ctx](const CLI::results_t& v) -> bool {
        if (v.size() != 1) {
            return false;
        }
        auto parsed = parse_validity_start(v[0]);
        if (!parsed) {
            return false;
        }
        ctx->validity_start = *parsed;
        ctx->custom_validity = true;
        return true;
    };
    CLI::callback_t validity_duration_cb = [ctx](const CLI::results_t& v) -> bool {
        if (v.size() != 1) {
            return false;
        }
        auto parsed = parse_duration_hours(v[0]);
        if (!parsed) {
            return false;
        }
        ctx->validity_duration = *parsed;
        ctx->custom_validity = true;
        return true;
    };
    request
        ->add_option("--validity-start", validity_start_cb,
            "AT validity start: 'YYYY-MM-DD[THH:MM:SS]' or relative '+Nd/h/w'")
        ->default_str("now");
    request->add_option("--validity-duration", validity_duration_cb, "AT validity duration: 'Nh', 'Nd', 'Nw'")
        ->default_str("1w");
    request->callback([ctx]() { ctx->action = [ctx]() { request_ticket(*ctx); }; });

    auto prune = app->add_subcommand("prune", "delete expired authorization tickets");
    auto prune_dry = prune->add_flag("--dry-run,-n", "list only; do not delete");
    prune->callback([ctx, prune_dry]() {
        const bool dry_run = prune_dry->as<bool>();
        ctx->action = [ctx, dry_run]() { prune_expired_tickets(ctx->cfg, current_time(), dry_run); };
    });

    // Default when no subcommand is picked: list.
    app->final_callback([ctx]() {
        if (!ctx->action) {
            ctx->action = [ctx]() { list_tickets(*ctx); };
        }
        ctx->action();
    });

    return app;
}

namespace
{

struct AuthoritiesFromCtl
{
    EnrolmentAuthority ea;
    AuthorizationAuthority aa;
};

/**
 * \brief Look up the EA (encryptedEcSignature recipient) and AA (outer encryption)
 * from the current Root CA's stored CTL.
 * \throws if the CTL is missing, either authority is not listed, or encryption keys are missing
 */
AuthoritiesFromCtl lookup_authorities(Context& ctx)
{
    auto processor = process_stored_ctl(*ctx.cfg.trust_lists, ctx.cfg.security, ctx.cfg.root_ca_hid8);
    return AuthoritiesFromCtl { require_enrolment_authority(processor, ctx.cfg.root_ca_hid8),
        require_authorization_authority(processor, ctx.cfg.root_ca_hid8) };
}

/// \brief Format one appPermissions entry as 'PSID[:HEX_SSP]', mirroring --permission.
std::string format_app_permission(const Vanetza_Security_PsidSsp_t& entry)
{
    std::string out = std::to_string(entry.psid);
    if (entry.ssp) {
        const auto& ssp = *entry.ssp;
        const std::uint8_t* buf = nullptr;
        std::size_t len = 0;
        if (ssp.present == Vanetza_Security_ServiceSpecificPermissions_PR_bitmapSsp) {
            buf = ssp.choice.bitmapSsp.buf;
            len = ssp.choice.bitmapSsp.size;
        } else if (ssp.present == Vanetza_Security_ServiceSpecificPermissions_PR_opaque) {
            buf = ssp.choice.opaque.buf;
            len = ssp.choice.opaque.size;
        }
        if (buf && len > 0) {
            out += ":";
            out += hexstring(buf, len);
        }
    }
    return out;
}

/// \brief Print one stored AT to stdout: header line, validity range, appPermissions.
void describe_ticket(Context& ctx, const HashedId8& at_id, const Certificate& at)
{
    Clock::time_point start = at.valid_since();
    Clock::time_point stop = at.valid_until();
    Clock::time_point now = current_time();
    const char* state = (now < start) ? "[not yet valid]" : (now > stop) ? "[expired]" : "[valid now]";
    std::cout << hexstring(at_id);
    auto name = at.get_name();
    if (!name.empty()) {
        std::cout << " " << name;
    }
    std::cout << " " << state << "\n";
    std::cout << "  valid: " << Clock::at(start) << " until " << Clock::at(stop) << "\n";

    const auto* ap = at.raw().toBeSigned.appPermissions;
    if (ap && ap->list.count > 0) {
        std::cout << "  permissions:";
        for (int i = 0; i < ap->list.count; ++i) {
            if (ap->list.array[i]) {
                std::cout << " " << format_app_permission(*ap->list.array[i]);
            }
        }
        std::cout << "\n";
    }
}

/// \brief Print every stored AT plus a count line.
void list_tickets(Context& ctx)
{
    std::size_t count = 0;
    for (const auto& id : ctx.cfg.tickets->list()) {
        if (count == 0) {
            std::cout << "Stored authorization ticket(s):\n";
        }
        ++count;
        auto at = ctx.cfg.tickets->fetch(id);
        if (!at) {
            std::cout << hexstring(id) << " [unreadable]\n";
            continue;
        }
        describe_ticket(ctx, id, *at);
    }
    if (count == 0) {
        std::cout << "No authorization tickets stored.\n";
    } else {
        std::cout << count << " authorization ticket(s) total.\n";
    }
}

/**
 * \brief One AA round-trip: fresh AT key, build, POST, decrypt, parse, store.
 *
 * EA/AA are looked up by the caller so they can be reused across a batch.
 * \throws on any failure
 */
void request_one_ticket(Context& ctx, const Certificate& ec, const AuthoritiesFromCtl& auth,
    const boost::optional<ValidityPeriodHint>& validity)
{
    ScopedKeyPair scoped_at_key(*ctx.cfg.security, ctx.key_type);

    AuthorizationRequestParameters params;
    params.ec = &ec;
    params.ea_certificate = &auth.ea.certificate;
    params.aa_certificate = &auth.aa.certificate;
    params.verification_key = scoped_at_key.public_key();
    params.permissions = ctx.permissions;
    params.hash_algo = ctx.hash_algo;
    params.validity_period = validity;

    EncryptedData encrypted_data = build_authorization_request(*ctx.cfg.security, params);

    auto query = HttpQuery::from_url(ctx.url(auth.aa));
    auto encoded = encrypted_data.encode();
    auto req_hash = ctx.cfg.security->calculate_sha256_hash(encoded.data(), encoded.size());
    auto response = http_post(query, "application/x-its-request", encoded);

    if (response.result() != boost::beast::http::status::ok) {
        throw HttpException("AA returned an unexpected HTTP status for the authorization request",
            std::move(response));
    } else if (response[boost::beast::http::field::content_type] != "application/x-its-response") {
        throw HttpException("expected application/x-its-response");
    }

    if (!encrypted_data.decode(response.body().data(), response.body().size())) {
        throw DecodingFailure("decoding encrypted AT response failed");
    }
    ByteBuffer dec_resp = encrypted_data.decrypt();

    AuthorizationResponse at_resp = parse_authorization_response(*ctx.cfg.security, dec_resp, auth.aa.certificate);
    if (!check_request_hash(req_hash, at_resp.request_hash)) {
        throw VerificationFailure("mismatch between request and response hash");
    }
    if (at_resp.code != Vanetza_Security_AuthorizationResponseCode_ok) {
        throw std::runtime_error("AA response code: " + vanetza::pki::to_string(at_resp.code));
    }

    Certificate& at = *at_resp.certificate;
    HashedId8 at_id = at.calculate_hashed_id8(*ctx.cfg.security);
    scoped_at_key.commit();
    ctx.cfg.tickets->store(at);
    std::cout << "Stored new AT " << hexstring(at_id) << "\n";
    describe_ticket(ctx, at_id, at);
}

/// \brief Validate preconditions, look up the AA, then request `ctx.count` ATs in sequence.
void request_ticket(Context& ctx)
{
    if (ctx.permissions.empty()) {
        throw UsageError("at least one --permission must be specified");
    }

    // Preconditions and authority lookup are shared across the whole batch.
    auto ec_id = ctx.cfg.station->get_ec_identifier();
    if (!ec_id) {
        throw UsageError("no EC available", "run 'enrolment initial' first");
    }
    auto ec = ctx.cfg.enrolment_credentials->fetch(*ec_id);
    if (!ec) {
        throw UsageError("EC certificate missing from storage", "re-run 'enrolment initial'");
    }
    if (!ctx.cfg.security->can_sign(ec->get_public_key())) {
        throw UsageError("no EC private key available", "re-run 'enrolment initial'");
    }

    // Send a validityPeriod hint only when the user explicitly set --validity-start or --validity-duration.
    // Otherwise leave it out so the AA picks unilaterally.
    boost::optional<ValidityPeriodHint> validity;
    if (ctx.custom_validity) {
        validity = ValidityPeriodHint { ctx.validity_start, ctx.validity_duration };
    }

    AuthoritiesFromCtl auth = lookup_authorities(ctx);
    HashedId8 aa_hid8 = auth.aa.certificate.calculate_hashed_id8(*ctx.cfg.security);
    std::cout << "Authorizing against AA " << hexstring(aa_hid8) << " at " << ctx.url(auth.aa) << "\n";

    for (unsigned i = 1; i <= ctx.count; ++i) {
        if (ctx.count > 1) {
            std::cout << "--- AT " << i << " of " << ctx.count << " ---\n";
        }
        request_one_ticket(ctx, *ec, auth, validity);
    }
}

} // namespace

} // namespace pki
} // namespace vanetza

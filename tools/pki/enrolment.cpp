#include "enrolment.hpp"
#include "asn1.hpp"
#include "certificate.hpp"
#include "certificate_trust_list.hpp"
#include "ea_request.hpp"
#include "ea_response.hpp"
#include "encrypted_data.hpp"
#include "exception.hpp"
#include "hexstring.hpp"
#include "http.hpp"
#include "pem.hpp"
#include "response_codes.hpp"
#include "time.hpp"
#include "validation.hpp"
#include <vanetza/common/its_aid.hpp>
#include <CLI/ExtraValidators.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <fstream>
#include <sstream>
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

    const MainConfig& cfg;
    std::function<void()> action;
    bool forced = false;
    KeyType key_type = KeyType::BrainpoolP256r1;
    HashAlgorithm hash_algo = HashAlgorithm::SHA256;

    struct Bootstrap
    {
        PrivateKey private_key;
        PublicKey public_key;
        std::string identifier;
    };
    Bootstrap bootstrap;
};

std::map<std::string, KeyType> key_type_map = { { "NistP256", KeyType::NistP256 },
    { "BrainpoolP256r1", KeyType::BrainpoolP256r1 }, { "BrainpoolP384r1", KeyType::BrainpoolP384r1 } };

std::map<std::string, HashAlgorithm> hash_algo_map = { { "SHA256", HashAlgorithm::SHA256 },
    { "SHA384", HashAlgorithm::SHA384 } };

void check_enrolment_status(Context&);
void perform_initial_enrolment(Context&);
void perform_enrolment_renewal(Context&);

} // namespace

std::shared_ptr<CLI::App> build_enrolment_command(const MainConfig& cfg)
{
    auto ctx = std::make_shared<Context>(cfg);
    auto app = std::make_shared<CLI::App>("enrolment of ITS station at PKI", "enrolment");
    app->alias("enrol");

    CLI::callback_t canonical_keyfile_cb = [ctx](const CLI::results_t& keyfiles) -> bool {
        if (keyfiles.size() != 1) {
            return false;
        }
        std::ifstream ifs(keyfiles[0]);
        std::stringstream buffer;
        buffer << ifs.rdbuf();
        auto key = read_pem_private_key(buffer.str());
        if (key) {
            ctx->bootstrap.private_key = *key;
            ctx->bootstrap.public_key = derive_public_key(*key);
            return true;
        } else {
            return false;
        }
    };

    auto initial = app->add_subcommand("initial", "enrol with initial credentials (bootstrap)");
    initial->alias("init");
    initial->add_flag("--force", ctx->forced, "enforce initial enrolment");
    initial->add_option("--canonical-id", ctx->bootstrap.identifier, "canonical identifier")->required();
    initial->add_option("--canonical-keyfile", canonical_keyfile_cb, "canonical key (PEM encoded file)")
        ->required()
        ->check(CLI::ExistingFile);
    initial->add_option("--key-type", ctx->key_type, "type of generated verification key")
        ->default_val(KeyType::BrainpoolP256r1)
        ->capture_default_str()
        ->transform(CLI::CheckedTransformer(key_type_map, CLI::ignore_case));
    initial->add_option("--hash-algorithm", ctx->hash_algo, "hash algorithm for signing")
        ->default_val(HashAlgorithm::SHA256)
        ->capture_default_str()
        ->transform(CLI::CheckedTransformer(hash_algo_map, CLI::ignore_case));

    initial->callback([ctx]() {
        ctx->action = [ctx]() {
            // will initial enrolment overwrite an existing EC identifier?
            auto ec_id = ctx->cfg.station->get_ec_identifier();
            if (!ec_id || ctx->forced) {
                perform_initial_enrolment(*ctx);
            } else {
                throw UsageError("EC identifier is already set", "pass --force to overwrite");
            }
        };
    });

    auto renewal = app->add_subcommand("renewal", "renew enrolment credential (re-keying)");
    renewal->alias("renew");
    renewal->add_option("--key-type", ctx->key_type, "type of generated verification key")
        ->default_val(KeyType::BrainpoolP256r1)
        ->capture_default_str()
        ->transform(CLI::CheckedTransformer(key_type_map, CLI::ignore_case));
    renewal->add_option("--hash-algorithm", ctx->hash_algo, "hash algorithm for signing")
        ->default_val(HashAlgorithm::SHA256)
        ->capture_default_str()
        ->transform(CLI::CheckedTransformer(hash_algo_map, CLI::ignore_case));
    renewal->callback([ctx]() { ctx->action = [ctx]() { perform_enrolment_renewal(*ctx); }; });

    auto status = app->add_subcommand("status", "show enrolment status");
    status->callback([ctx]() { ctx->action = [ctx]() { check_enrolment_status(*ctx); }; });

    app->final_callback([ctx]() {
        if (ctx->action) {
            ctx->action();
        } else {
            check_enrolment_status(*ctx);
        }
    });

    return app;
}

namespace
{

void check_enrolment_status(Context& ctx)
{
    // has EC identifier set?
    boost::optional<HashedId8> ec_id = ctx.cfg.station->get_ec_identifier();

    // has EC certificate stored?
    boost::optional<Certificate> ec_cert;
    if (ec_id) {
        ec_cert = ctx.cfg.enrolment_credentials->fetch(*ec_id);
    }

    // can station sign with EC certificate (i.e., is the private key available)?
    bool can_sign = false;
    if (ec_cert) {
        can_sign = ctx.cfg.security->can_sign(ec_cert->get_public_key());
    }

    auto canonical_identifier = ctx.cfg.station->get_canonical_identifier();
    std::cout << "Canonical identifier: " << (canonical_identifier.empty() ? "[unknown]" : canonical_identifier)
              << "\n";
    std::cout << "EC identifier: " << (ec_id ? hexstring(*ec_id) : "[unknown]") << "\n";
    std::cout << "EC certificate: " << (ec_cert ? (ec_cert->get_name() + " [available]") : "[unavailable]") << "\n";
    if (ec_cert) {
        Clock::time_point start = ec_cert->valid_since();
        Clock::time_point stop = ec_cert->valid_until();
        std::cout << "EC certificate validity: " << Clock::at(start) << " until " << Clock::at(stop);
        Clock::time_point now = current_time();
        if (now >= start && now <= stop) {
            std::cout << " [valid now]\n";
            if (now + std::chrono::hours(24 * 7 * 12) > stop) {
                std::cout << "!! EC certificate expires in less than 12 weeks, you should renew it !!\n";
            }
        } else if (now < start) {
            std::cout << " [not yet valid]\n";
        } else {
            std::cout << " [expired]\n";
        }
    }
    std::cout << "EC suitable for signing: " << (can_sign ? "yes" : "no") << "\n";
}

EnrolmentAuthority lookup_enrolment_authority(Context& ctx)
{
    std::cout << "Root CA " << hexstring(ctx.cfg.root_ca_hid8) << "\n";
    auto processor = process_stored_ctl(*ctx.cfg.trust_lists, ctx.cfg.security, ctx.cfg.root_ca_hid8);
    return require_enrolment_authority(processor, ctx.cfg.root_ca_hid8);
}

/**
 * \brief Shared request/response round-trip for initial enrolment and renewal.
 *
 * Builds the EA-encrypted request, POSTs it, decrypts/parses the response,
 * stores the returned EC, sets the station's active EC identifier, and commits
 * the new verification key pair.
 * \throws on any failure along the way
 */
void perform_enrolment(Context& ctx, const EnrolmentRequestParameters& params, const EnrolmentAuthority& ea,
    ScopedKeyPair& scoped_verification_key)
{
    HashedId8 ea_cert_hid8 = ea.certificate.calculate_hashed_id8(*ctx.cfg.security);
    std::cout << "Enroling against EA certificate: " << hexstring(ea_cert_hid8) << "\n";

    EncryptedData encrypted_data = build_enrolment_request(*ctx.cfg.security, params, ea.certificate);

    // Some PKIs have EA entry which does not have ITS access point
    auto ea_url = ea.its_access_point.empty() ? ea.aa_access_point : ea.its_access_point;
    std::cout << "Enroling at EA URL: " << ea_url << "\n";
    auto query = HttpQuery::from_url(ea_url);
    auto encoded_encrypted_data = encrypted_data.encode();
    auto sha256_encrypted_data =
        ctx.cfg.security->calculate_sha256_hash(encoded_encrypted_data.data(), encoded_encrypted_data.size());

    auto response = http_post(query, "application/x-its-request", encoded_encrypted_data);
    if (response.result() != boost::beast::http::status::ok) {
        throw HttpException("EA returned an unexpected HTTP status for the enrolment request");
    } else if (response[boost::beast::http::field::content_type] != "application/x-its-response") {
        throw HttpException("expected application/x-its-response");
    }

    if (!encrypted_data.decode(response.body().data(), response.body().size())) {
        throw DecodingFailure("decoding encrypted response failed");
    }
    ByteBuffer dec_resp = encrypted_data.decrypt();

    EnrolmentResponse ec_resp = parse_enrolment_response(*ctx.cfg.security, dec_resp, ea.certificate);

    if (!check_request_hash(sha256_encrypted_data, ec_resp.request_hash)) {
        throw VerificationFailure("mismatch between request and response hash");
    }

    if (ec_resp.code != Vanetza_Security_EnrolmentResponseCode_ok) {
        throw std::runtime_error("inner EC response code: " + vanetza::pki::to_string(ec_resp.code));
    }

    Certificate& ec = *ec_resp.certificate;
    auto ec_hid8 = ec.calculate_hashed_id8(*ctx.cfg.security);
    scoped_verification_key.commit();
    ctx.cfg.enrolment_credentials->store(ec);
    ctx.cfg.station->set_ec_identifier(ec_hid8);
    std::cout << "Stored new EC with HashedId8 = " << hexstring(ec_hid8) << "\n";

    // safety check
    if (ctx.cfg.security->can_sign(ec.get_public_key())) {
        std::cout << "Station can sign with received EC\n";
    } else {
        std::cerr << "Station cannot sign with received EC\n";
    }
}

void perform_initial_enrolment(Context& ctx)
{
    EnrolmentAuthority ea = lookup_enrolment_authority(ctx);

    // security module stores created private key in its credential storage
    ScopedKeyPair scoped_verification_key(*ctx.cfg.security, ctx.key_type);

    // set permanent canonical identifier
    ctx.cfg.station->set_canonical_identifier(ctx.bootstrap.identifier);
    std::cout << "Canonical identifier: " << ctx.bootstrap.identifier << "\n";

    // load bootstrap keys (only for this scope)
    ScopedCredential scoped_bootstrap_keys { *ctx.cfg.credentials, ctx.bootstrap.public_key,
        ctx.bootstrap.private_key };

    std::cout << "Canonical public key X=" << hexstring(ctx.bootstrap.public_key.x);
    if (!ctx.bootstrap.public_key.y.empty()) {
        std::cout << " Y=" << hexstring(ctx.bootstrap.public_key.y);
    }
    std::cout << "\n";

    EnrolmentRequestParameters params;
    params.its_id = ctx.bootstrap.identifier;
    params.verification_key = scoped_verification_key.public_key();
    params.outer_signer_key = ctx.bootstrap.public_key;
    params.hash_algo = ctx.hash_algo;

    perform_enrolment(ctx, params, ea, scoped_verification_key);
}

void perform_enrolment_renewal(Context& ctx)
{
    auto ec_id = ctx.cfg.station->get_ec_identifier();
    if (!ec_id) {
        throw UsageError("no EC to renew", "run 'enrolment initial' first");
    }
    auto ec_cert = ctx.cfg.enrolment_credentials->fetch(*ec_id);
    if (!ec_cert) {
        throw UsageError("EC certificate missing from storage", "re-run 'enrolment initial'");
    }
    PublicKey ec_key = ec_cert->get_public_key();
    if (!ctx.cfg.security->can_sign(ec_key)) {
        throw UsageError("no EC private key available", "re-run 'enrolment initial'");
    }

    EnrolmentAuthority ea = lookup_enrolment_authority(ctx);

    // Fresh verification key for the new EC
    // TS 102 941 §6.2.3.2.1 mandates a new key pair on every enrolment request).
    ScopedKeyPair scoped_verification_key(*ctx.cfg.security, ctx.key_type);

    std::cout << "Renewing EC " << hexstring(*ec_id) << "\n";

    EnrolmentRequestParameters params;
    // TS 102 941 §6.2.3.2.1 itsId carries the raw 8 bytes of HashedId8(current EC).
    params.its_id.assign(ec_id->octets.begin(), ec_id->octets.end());
    params.verification_key = scoped_verification_key.public_key();
    params.outer_signer_key = ec_key;
    params.outer_signer_certificate = &ec_cert.value();
    params.hash_algo = ctx.hash_algo;

    perform_enrolment(ctx, params, ea, scoped_verification_key);
}

} // namespace

} // namespace pki
} // namespace vanetza

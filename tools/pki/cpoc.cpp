#include "cpoc.hpp"
#include "asn1.hpp"
#include "certificate.hpp"
#include "certificate_storage.hpp"
#include "certificate_trust_list.hpp"
#include "exception.hpp"
#include "hashed_id8.hpp"
#include "hashed_id8_validator.hpp"
#include "http.hpp"
#include "time.hpp"
#include "validation.hpp"
#include <boost/beast/http/field.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <functional>

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

    std::filesystem::path ectl_file() const
    {
        return cfg.data_path / "ectl.ctl";
    }

    const MainConfig& cfg;
    std::string cpoc_url = "https://cpoc.jrc.ec.europa.eu/L0";
    HashedId8 hid8;
    std::function<void()> action;
};

const HashedId8Validator hid8_validator;

Certificate fetch_tlm_certificate(const std::string& base_url, const HashedId8* id)
{
    auto query = HttpQuery::from_url(base_url + "/gettlmcertificate/" + (id ? hexstring(*id) : ""));
    auto response = http_get(query);
    if (response.result() != boost::beast::http::status::ok) {
        throw HttpException("CPOC returned an unexpected HTTP status when fetching TLM certificate");
    } else if (response[boost::beast::http::field::content_type] != "application/octet-stream") {
        throw HttpException("did not receive bytes from CPOC when fetching TLM certificate");
    } else {
        Certificate cert;
        if (!cert.decode(response.body())) {
            throw DecodingFailure("decoding received TLM certificate failed");
        } else {
            return cert;
        }
    }
}

boost::optional<std::tuple<Certificate, HashedId8>> lookup_default_tlm_certificate(const Context& context)
{
    const CertificateStorage& storage = *context.cfg.tlm;
    boost::optional<std::tuple<Certificate, HashedId8>> match;
    Clock::time_point now = current_time();

    for (const HashedId8& hid8 : storage.list()) {
        boost::optional<Certificate> candidate = storage.fetch(hid8);
        if (candidate && is_currently_valid(*candidate, now)) {
            if (!match) {
                match = std::make_tuple(*candidate, hid8);
            } else if (std::get<0>(*match).valid_since() < candidate->valid_since()) {
                match = std::make_tuple(*candidate, hid8);
            }
        }
    }

    return match;
}

void list_tlm(Context& context)
{
    const Clock::time_point now = current_time();
    std::cout << "Trusted TLM certificates are:\n";
    for (const HashedId8& hid8 : context.cfg.tlm->list()) {
        boost::optional<Certificate> cert = context.cfg.tlm->fetch(hid8);
        if (!cert) {
            std::cout << "- " << hexstring(hid8) << "\n";
            continue;
        }
        const std::string name = cert->get_name();
        std::cout << "- " << (name.empty() ? hexstring(hid8) : name + " (" + hexstring(hid8) + ")") << "\n";
        const char* status = "valid";
        if (now < cert->valid_since()) {
            status = "not yet valid";
        } else if (now > cert->valid_until()) {
            status = "expired";
        }
        std::cout << "  |-> valid from " << Clock::at(cert->valid_since()) << " until "
                  << Clock::at(cert->valid_until()) << " [" << status << "]\n";
    }
}

void fetch_tlm(Context& context, const HashedId8* id, bool dry_run)
{
    Certificate tlm = fetch_tlm_certificate(context.cpoc_url, id);
    const HashedId8 tlm_hid8 = tlm.calculate_hashed_id8(*context.cfg.security);
    if (id && *id != tlm_hid8) {
        throw VerificationFailure("fetched TLM certificate's HashedId8 does not match requested HashedId8");
    }
    const std::string name = tlm.get_name();
    const std::string hex_hid8 = hexstring(tlm_hid8);
    if (dry_run) {
        std::cout << "CPOC can provide TLM certificate "
                  << (name.empty() ? hex_hid8 : "\"" + name + "\" (" + hex_hid8 + ")")
                  << ". Storage unchanged in this dry run.\n";
        return;
    }
    context.cfg.tlm->store(tlm);
    if (name.empty()) {
        std::cout << "Added TLM certificate (" << hex_hid8 << ")\n";
    } else {
        std::cout << "Added TLM certificate \"" << name << "\" (" << hex_hid8 << ")\n";
    }
}

void discard_tlm(Context& context, const HashedId8& id)
{
    if (context.cfg.tlm->erase(id)) {
        std::cout << "Removed " << hexstring(id) << " from trusted TLM certificates\n";
    } else {
        std::cout << "No TLM certificate with " << hexstring(id) << " found in local storage\n";
    }
}

std::shared_ptr<CLI::App> build_tlm_command(std::shared_ptr<Context> context)
{
    auto app = std::make_shared<CLI::App>("Trust List Manager", "tlm");

    auto list = app->add_subcommand("list", "list all trusted TLM certificates");
    list->callback([context]() { context->action = [context]() { list_tlm(*context); }; });

    auto fetch = app->add_subcommand("fetch", "fetch a TLM certificate from CPOC (omit the id to fetch the latest)");
    auto fetch_id =
        fetch->add_option("hid8", context->hid8, "HashedId8 of the TLM certificate to fetch; omit for the latest")
            ->check(hid8_validator);
    auto fetch_dry = fetch->add_flag("--dry-run,-n", "do not store the fetched certificate");
    fetch->callback([context, fetch_id, fetch_dry]() {
        const bool has_id = fetch_id->count() > 0;
        const bool dry_run = fetch_dry->as<bool>();
        context->action = [context, has_id, dry_run]() {
            fetch_tlm(*context, has_id ? &context->hid8 : nullptr, dry_run);
        };
    });

    auto discard = app->add_subcommand("discard", "discard a TLM certificate (distrust it)");
    discard->add_option("hid8", context->hid8, "HashedId8 of the TLM certificate to discard")
        ->required()
        ->check(hid8_validator);
    discard->callback([context]() { context->action = [context]() { discard_tlm(*context, context->hid8); }; });

    app->final_callback([context]() {
        if (!context->action) {
            context->action = [context]() { list_tlm(*context); };
        }
        context->action();
    });

    return app;
}

void list_ectl(Context& context)
{
    CertificateTrustList ctl = CertificateTrustList::from_file(context.ectl_file());
    std::cout << "ECTL contains:\n";
    CtlListingVisitor visitor(*context.cfg.security);
    ctl.visit_tlm_ctl(visitor);
}

// tlm_id == nullptr -> use the locally known latest TLM certificate.
void fetch_ectl(Context& context, const HashedId8* tlm_id, bool dry_run)
{
    CertificateStorage& storage = *context.cfg.tlm;

    HashedId8 tlm_hid8;
    if (tlm_id) {
        tlm_hid8 = *tlm_id;
    } else {
        auto lookup = lookup_default_tlm_certificate(context);
        if (!lookup) {
            throw UsageError("no TLM certificate found", "run 'cpoc tlm fetch' first");
        }
        tlm_hid8 = std::get<1>(*lookup);
    }

    struct UpdateVisitor : CtlVisitor
    {
        UpdateVisitor(std::shared_ptr<CertificateStorage> certs) : certificates(certs)
        {
        }

        void add_root_ca(const Vanetza_Security_RootCaEntry_t& rca) override
        {
            Certificate root_ca { rca.selfsignedRootCa };
            certificates->store(root_ca);
        }

        std::shared_ptr<CertificateStorage> certificates;
    };

    auto query = HttpQuery::from_url(context.cpoc_url + "/getectl/" + hexstring(tlm_hid8));
    auto response = http_get(query);
    if (response.result() != boost::beast::http::status::ok) {
        throw HttpException("CPOC returned an unexpected HTTP status when fetching full ECTL");
    } else if (response[boost::beast::http::field::content_type] != "application/octet-stream") {
        throw HttpException("did not receive bytes from CPOC when fetching full ECTL");
    }

    CertificateTrustList tlm_message;
    if (!tlm_message.decode(response.body())) {
        throw DecodingFailure("decoding received TLM certificate list message failed");
    } else if (const Vanetza_Security_SignedData_t* sdata = get_signed_data(tlm_message.raw())) {
        const Vanetza_Security_EtsiTs103097Certificate_t* ectl_certificate = nullptr;
        if (sdata->signer.present == Vanetza_Security_SignerIdentifier_PR_digest) {
            if (!equals(sdata->signer.choice.digest, tlm_hid8)) {
                throw VerificationFailure("expected a different HashedId8 digest in response message");
            }
        } else if (sdata->signer.present == Vanetza_Security_SignerIdentifier_PR_certificate) {
            const Vanetza_Security_SequenceOfCertificate& certlist = sdata->signer.choice.certificate;
            if (certlist.list.count >= 1) {
                ectl_certificate = certlist.list.array[0];
                HashedId8 cert_hid8 = calculate_hashed_id8(*context.cfg.security, *ectl_certificate);
                if (cert_hid8 != tlm_hid8) {
                    throw VerificationFailure("signing certificate's digest does not match requested HashedId8");
                }
            } else {
                throw DecodingFailure("missing certificate used for signing");
            }
        } else {
            throw VerificationFailure("received ECTL message is not signed by expected TLM HashedId8");
        }

        boost::optional<Certificate> stored_tlm = storage.fetch(tlm_hid8);
        if (!stored_tlm) {
            if (!ectl_certificate) {
                throw UsageError("missing TLM certificate to verify ECTL", "run 'cpoc tlm fetch' first");
            }
            stored_tlm = Certificate(*ectl_certificate);
            if (!dry_run) {
                storage.store(*stored_tlm);
            }
        }

        if (!validate(*context.cfg.security, *sdata, stored_tlm->raw())) {
            throw VerificationFailure("signature verification of ECTL failed");
        }

        if (dry_run) {
            std::cout << "ECTL signature verified. Storage unchanged in this dry run.\n";
            return;
        }

        write(context.ectl_file(), ByteBuffer { response.body().begin(), response.body().end() });
        std::cout << "Stored ECTL\n";

        UpdateVisitor visitor(context.cfg.root_ca);
        tlm_message.visit_tlm_ctl(visitor);
    } else {
        throw DecodingFailure("message contains no signed data");
    }
}

std::shared_ptr<CLI::App> build_ectl_command(std::shared_ptr<Context> context)
{
    auto app = std::make_shared<CLI::App>("European Certificate Trust List", "ectl");

    auto list = app->add_subcommand("list", "list trusted CAs from the locally stored ECTL");
    list->callback([context]() { context->action = [context]() { list_ectl(*context); }; });

    auto fetch =
        app->add_subcommand("fetch", "fetch the full ECTL signed by the TLM (omit the id to use the latest known TLM)");
    auto fetch_id =
        fetch->add_option("hid8", context->hid8, "HashedId8 of the TLM; omit to use the latest known TLM certificate")
            ->check(hid8_validator);
    auto fetch_dry = fetch->add_flag("--dry-run,-n", "fetch and verify only; do not store the ECTL");
    fetch->callback([context, fetch_id, fetch_dry]() {
        const bool has_id = fetch_id->count() > 0;
        const bool dry_run = fetch_dry->as<bool>();
        context->action = [context, has_id, dry_run]() {
            fetch_ectl(*context, has_id ? &context->hid8 : nullptr, dry_run);
        };
    });

    app->final_callback([context]() {
        if (!context->action) {
            context->action = [context]() { list_ectl(*context); };
        }
        context->action();
    });

    return app;
}

} // namespace

std::shared_ptr<CLI::App> build_cpoc_command(const MainConfig& config)
{
    auto ctx = std::make_shared<Context>(config);
    auto app = std::make_shared<CLI::App>("C-ITS Point of Contact Protocol", "cpoc");
    app->add_option("--url", ctx->cpoc_url, "CPOC base URL")->capture_default_str();

    app->add_subcommand(build_ectl_command(ctx));
    app->add_subcommand(build_tlm_command(ctx));
    app->require_subcommand();

    return app;
}

} // namespace pki
} // namespace vanetza

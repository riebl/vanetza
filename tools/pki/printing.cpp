#include "printing.hpp"
#include "certificate.hpp"
#include "exception.hpp"
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/asn1/security/EtsiTs103097Certificate.h>
#include <vanetza/asn1/security/EtsiTs103097Data.h>
#include <vanetza/common/byte_buffer.hpp>
#include <boost/optional/optional.hpp>
#include <fstream>
#include <iostream>
#include <string>

namespace vanetza
{
namespace pki
{

namespace
{

struct Context
{
    std::string input_file;
    bool input_stdin = false;
    bool print_role = false; // certificate only
};

const char* role_token(CertificateRole role)
{
    switch (role) {
        case CertificateRole::RootCa:
            return "root-ca";
        case CertificateRole::EnrolmentAuthority:
            return "enrolment-authority";
        case CertificateRole::AuthorizationAuthority:
            return "authorization-authority";
        case CertificateRole::EnrolmentCredential:
            return "enrolment-credential";
        case CertificateRole::AuthorizationTicket:
            return "authorization-ticket";
        case CertificateRole::Tlm:
            return "tlm";
        case CertificateRole::Unknown:
            return "unknown";
    }
    return "unknown";
}

// Read the OER bytes from the chosen input source, or boost::none if neither
// was given (should not happen: the input-source group requires exactly one).
boost::optional<ByteBuffer> read_input(const Context& ctx)
{
    ByteBuffer input;
    if (!ctx.input_file.empty()) {
        std::ifstream ifs(ctx.input_file, std::ios::binary);
        std::istreambuf_iterator<char> begin(ifs), end;
        input.assign(begin, end);
    } else if (ctx.input_stdin) {
        std::istreambuf_iterator<char> begin(std::cin), end;
        input.assign(begin, end);
    } else {
        return boost::none;
    }
    return input;
}

void add_input_source(CLI::App& app, Context& ctx)
{
    auto group = app.add_option_group("input source", "read data from the given source");
    group->add_option("-f,--file", ctx.input_file, "filename")->check(CLI::ExistingFile);
    group->add_flag("--stdin", ctx.input_stdin, "read from stdin");
    group->require_option(1);
}

void print_certificate(const ByteBuffer& input, bool role)
{
    if (role) {
        Certificate cert;
        if (cert.decode(input)) {
            std::cout << role_token(certificate_role(cert)) << "\n";
        } else {
            throw DecodingFailure("EtsiTs103097Certificate");
        }
        return;
    }
    asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs103097Certificate_t>
        cert(asn_DEF_Vanetza_Security_EtsiTs103097Certificate);
    if (cert.decode(input)) {
        xer_fprint(stdout, &asn_DEF_Vanetza_Security_EtsiTs103097Certificate, &*cert);
    } else {
        throw DecodingFailure("EtsiTs103097Certificate");
    }
}

void print_data(const ByteBuffer& input)
{
    asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs103097Data_t> data(asn_DEF_Vanetza_Security_EtsiTs103097Data);
    if (data.decode(input)) {
        xer_fprint(stdout, &asn_DEF_Vanetza_Security_EtsiTs103097Data, &*data);
    } else {
        throw DecodingFailure("EtsiTs103097Data");
    }
}

void print_mgmt_data(const ByteBuffer& input)
{
    asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data_t> data(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    if (data.decode(input)) {
        xer_fprint(stdout, &asn_DEF_Vanetza_Security_EtsiTs102941Data, &*data);
    } else {
        throw DecodingFailure("EtsiTs102941Data");
    }
}

} // namespace

std::shared_ptr<CLI::App> build_print_command()
{
    auto ctx = std::make_shared<Context>();
    auto app = std::make_shared<CLI::App>("printing ASN.1 OER encoded certificates, trust lists and alike", "print");

    auto certificate = app->add_subcommand("certificate", "EtsiTs103097Certificate");
    certificate->alias("cert");
    add_input_source(*certificate, *ctx);
    certificate->add_flag("--role", ctx->print_role, "print the certificate's PKI role instead of its content");
    certificate->callback([ctx]() {
        if (auto input = read_input(*ctx)) {
            print_certificate(*input, ctx->print_role);
        }
    });

    auto data = app->add_subcommand("data", "EtsiTs103097Data");
    add_input_source(*data, *ctx);
    data->callback([ctx]() {
        if (auto input = read_input(*ctx)) {
            print_data(*input);
        }
    });

    auto mgmt = app->add_subcommand("mgmt-data", "EtsiTs102941Data");
    add_input_source(*mgmt, *ctx);
    mgmt->callback([ctx]() {
        if (auto input = read_input(*ctx)) {
            print_mgmt_data(*input);
        }
    });

    app->require_subcommand(1);
    return app;
}

} // namespace pki
} // namespace vanetza

#include "validation.hpp"
#include <vanetza/security/delegating_security_entity.hpp>
#include <boost/program_options.hpp>
#include <iostream>
#include <random>

using namespace vanetza;
using namespace vanetza::security;
namespace po = boost::program_options;

bool SecurityValidationCase::parse(const std::vector<std::string>& opts)
{
    po::options_description desc("Available options");
    desc.add_options()
        ("help", "Print out available options.")
        ("identities", po::value<unsigned>(&identities)->default_value(1), "Number of identities (certificates).")
        ("messages", po::value<unsigned>(&messages)->default_value(10000), "Number of messages.")
        ("signer", po::value<std::string>(&signer_info_type)->default_value("certificate"), "Signer embedded into the messages, may be 'certificate', 'hash' or 'chain'.")
    ;

    po::variables_map vm;
    po::store(po::command_line_parser(opts).options(desc).run(), vm);

    if (vm.count("help")) {
        std::cerr << desc << std::endl;

        return false;
    }

    try {
        po::notify(vm);

        if (signer_info_type != "certificate" && signer_info_type != "hash" && signer_info_type != "chain") {
            throw std::runtime_error("Invalid signer info type.");
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl << std::endl << desc << std::endl;

        return false;
    }

    return true;
}

int SecurityValidationCase::execute()
{
    DownPacket packet;
    packet.layer(OsiLayer::Application) = ByteBuffer { 0xC0, 0xFF, 0xEE };

    certificate_cache.insert(certificate_provider.own_certificate());
    certificate_cache.insert(certificate_provider.aa_certificate());
    trust_store.insert(certificate_provider.root_certificate());

    std::vector<NaiveCertificateProvider*> providers(identities, nullptr);
    std::vector<SignService> signers(identities);
    std::vector<SecurityEntity*> entities(identities, nullptr);
    std::vector<SecuredMessageV2> secured_messages(identities);

    for (unsigned i = 0; i < identities; i++) {
        providers[i] = new NaiveCertificateProvider(runtime);
        signers[i] = straight_sign_service(*providers[i], *crypto_backend, sign_header_policy);
        entities[i] = new DelegatingSecurityEntity(signers[i], verify_service);
        certificate_cache.insert(providers[i]->own_certificate());
    }

    if (signer_info_type == "hash") {
        // Sign one message with CAM profile, so the next message only includes the certificate hash
        EncapRequest initial_encap_request;
        initial_encap_request.plaintext_payload = packet;
        initial_encap_request.its_aid = aid::CA;
        entities[0]->encapsulate_packet(std::move(initial_encap_request));
    }

    for (unsigned i = 0; i < identities; i++) {
        if (signer_info_type == "certificate") {
            sign_header_policy.request_certificate();
        } else if (signer_info_type == "chain") {
            sign_header_policy.request_certificate_chain();
        }

        EncapRequest encap_request;
        encap_request.plaintext_payload = packet;
        encap_request.its_aid = aid::CA;

        EncapConfirm encap_confirm = entities[i]->encapsulate_packet(std::move(encap_request));
        secured_messages[i] = encap_confirm.sec_packet;
        auto signer_info = encap_confirm.sec_packet.header_field<HeaderFieldType::Signer_Info>();

        if (signer_info_type == "hash") {
            assert(signer_info && get_type(*signer_info) == SignerInfoType::Certificate_Digest_With_SHA256);
        } else if (signer_info_type == "certificate") {
            assert(signer_info && get_type(*signer_info) == SignerInfoType::Certificate);
        } else if (signer_info_type == "chain") {
            assert(signer_info && get_type(*signer_info) == SignerInfoType::Certificate_Chain);
        }
    }

    std::mt19937 gen(0);
    std::uniform_int_distribution<> dis(0, identities - 1);

    std::cout << "Starting benchmark for messages ... ";

    for (unsigned i = 0; i < messages; i++) {
        auto copy = secured_messages[dis(gen)];
        auto decap_confirm = security_entity.decapsulate_packet(std::move(copy));
        assert(decap_confirm.report == DecapReport::Success);
    }

    std::cout << "[Done]" << std::endl;

    return 0;
}

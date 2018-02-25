#include "validate_certificate_hash.hpp"
#include <iostream>

using namespace vanetza;
using namespace vanetza::security;

int SecurityValidateCertificateHashCase::execute()
{
    DownPacket packet;
    packet.layer(OsiLayer::Application) = ByteBuffer { 0xC0, 0xFF, 0xEE };

    // Sign one message with CAM profile, so the next message only includes the certificate hash
    EncapRequest initial_encap_request;
    initial_encap_request.plaintext_payload = packet;
    initial_encap_request.its_aid = aid::CA;
    security_entity.encapsulate_packet(std::move(initial_encap_request));

    EncapRequest encap_request;
    encap_request.plaintext_payload = packet;
    encap_request.its_aid = aid::CA;

    EncapConfirm encap_confirm = security_entity.encapsulate_packet(std::move(encap_request));

    certificate_cache.insert(certificate_provider.own_certificate());
    certificate_cache.insert(certificate_provider.aa_certificate());
    trust_store.insert(certificate_provider.root_certificate());

    auto message = encap_confirm.sec_packet;
    auto message_copy = message;

    DecapConfirm decap_confirm = security_entity.decapsulate_packet(std::move(message_copy));
    assert(decap_confirm.report == DecapReport::Success);

    std::cout << "Starting benchmark for messages including certificate hash..." << std::endl;

    for (unsigned i = 0; i < 10000; i++) {
        security_entity.decapsulate_packet(std::move(message_copy));
        assert(decap_confirm.report == DecapReport::Success);
    }

    std::cout << "Done." << std::endl;

    return 0;
}

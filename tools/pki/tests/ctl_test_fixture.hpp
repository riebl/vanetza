#pragma once

#include "asn1.hpp"
#include "certificate_trust_list.hpp"
#include "hashed_id8.hpp"
#include "keys.hpp"
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/CtlCommand.h>
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/asn1/security/EtsiTs103097Data.h>
#include <vanetza/asn1/security/Ieee1609Dot2Content.h>
#include <vanetza/asn1/security/RcaCertificateTrustListMessage.h>
#include <vanetza/asn1/security/SignedData.h>
#include <vanetza/asn1/security/TlmCertificateTrustListMessage.h>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/v3/basic_elements.hpp>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace vanetza
{
namespace pki
{

// Builds an RCA-signed CTL message. Internal: fills an EtsiTs102941Data with a
// CtlFormat, OER-encodes it, wraps in a signed message with the issuer's
// HashedId8 as signer (dummy signature). decode() the result into a
// CertificateTrustList for use in tests.
class TestRcaCtlBuilder
{
public:
    TestRcaCtlBuilder(const HashedId8& issuer, bool is_full, std::uint8_t sequence) : m_issuer(issuer)
    {
        m_data->version = 1;
        m_data->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_certificateTrustListRca;
        auto& format = m_data->content.choice.certificateTrustListRca;
        format.version = 1;
        format.nextUpdate = 0;
        format.isFullCtl = is_full ? 1 : 0;
        format.ctlSequence = sequence;
    }

    TestRcaCtlBuilder& add_aa(const PublicKey& key, const std::string& url)
    {
        auto* cmd = asn1::allocate<Vanetza_Security_CtlCommand_t>();
        cmd->present = Vanetza_Security_CtlCommand_PR_add;
        cmd->choice.add.present = Vanetza_Security_CtlEntry_PR_aa;
        auto& aa = cmd->choice.add.choice.aa;
        populate_stub_cert(aa.aaCertificate, key, "test-aa");
        OCTET_STRING_fromBuf(&aa.accessPoint, url.data(), url.size());
        asn_sequence_add(&m_data->content.choice.certificateTrustListRca.ctlCommands, cmd);
        return *this;
    }

    TestRcaCtlBuilder& add_ea(const PublicKey& key, const std::string& aa_access_point)
    {
        auto* cmd = asn1::allocate<Vanetza_Security_CtlCommand_t>();
        cmd->present = Vanetza_Security_CtlCommand_PR_add;
        cmd->choice.add.present = Vanetza_Security_CtlEntry_PR_ea;
        auto& ea = cmd->choice.add.choice.ea;
        populate_stub_cert(ea.eaCertificate, key, "test-ea");
        OCTET_STRING_fromBuf(&ea.aaAccessPoint, aa_access_point.data(), aa_access_point.size());
        // itsAccessPoint left null (OPTIONAL)
        asn_sequence_add(&m_data->content.choice.certificateTrustListRca.ctlCommands, cmd);
        return *this;
    }

    TestRcaCtlBuilder& add_dc(const std::string& url, const std::vector<HashedId8>& certs)
    {
        auto* cmd = asn1::allocate<Vanetza_Security_CtlCommand_t>();
        cmd->present = Vanetza_Security_CtlCommand_PR_add;
        cmd->choice.add.present = Vanetza_Security_CtlEntry_PR_dc;
        auto& dc = cmd->choice.add.choice.dc;
        OCTET_STRING_fromBuf(&dc.url, url.data(), url.size());
        for (const auto& id : certs) {
            auto* entry = asn1::allocate<Vanetza_Security_HashedId8_t>();
            OCTET_STRING_fromBuf(entry, reinterpret_cast<const char*>(id.octets.data()), id.octets.size());
            asn_sequence_add(&dc.cert, entry);
        }
        asn_sequence_add(&m_data->content.choice.certificateTrustListRca.ctlCommands, cmd);
        return *this;
    }

    TestRcaCtlBuilder& delete_cert(const HashedId8& id)
    {
        auto* cmd = asn1::allocate<Vanetza_Security_CtlCommand_t>();
        cmd->present = Vanetza_Security_CtlCommand_PR_delete;
        cmd->choice.Delete.present = Vanetza_Security_CtlDelete_PR_cert;
        OCTET_STRING_fromBuf(&cmd->choice.Delete.choice.cert, reinterpret_cast<const char*>(id.octets.data()),
            id.octets.size());
        asn_sequence_add(&m_data->content.choice.certificateTrustListRca.ctlCommands, cmd);
        return *this;
    }

    TestRcaCtlBuilder& delete_dc(const std::string& url)
    {
        auto* cmd = asn1::allocate<Vanetza_Security_CtlCommand_t>();
        cmd->present = Vanetza_Security_CtlCommand_PR_delete;
        cmd->choice.Delete.present = Vanetza_Security_CtlDelete_PR_dc;
        OCTET_STRING_fromBuf(&cmd->choice.Delete.choice.dc, url.data(), url.size());
        asn_sequence_add(&m_data->content.choice.certificateTrustListRca.ctlCommands, cmd);
        return *this;
    }

    CertificateTrustList build()
    {
        ByteBuffer inner_bytes = m_data.encode();

        asn1::asn1c_oer_wrapper<Vanetza_Security_RcaCertificateTrustListMessage_t>
            outer(asn_DEF_Vanetza_Security_RcaCertificateTrustListMessage);
        outer->protocolVersion = 3;
        outer->content = asn1::allocate<Vanetza_Security_Ieee1609Dot2Content_t>();
        outer->content->present = Vanetza_Security_Ieee1609Dot2Content_PR_signedData;

        auto* signed_data = asn1::allocate<Vanetza_Security_SignedData_t>();
        outer->content->choice.signedData = signed_data;
        signed_data->hashId = Vanetza_Security_HashAlgorithm_sha256;

        signed_data->signer.present = Vanetza_Security_SignerIdentifier_PR_digest;
        OCTET_STRING_fromBuf(&signed_data->signer.choice.digest, reinterpret_cast<const char*>(m_issuer.octets.data()),
            m_issuer.octets.size());

        signed_data->tbsData = asn1::allocate<Vanetza_Security_ToBeSignedData_t>();
        signed_data->tbsData->headerInfo.psid = aid::CTL;
        signed_data->tbsData->payload = asn1::allocate<Vanetza_Security_SignedDataPayload_t>();
        auto* inner_data = asn1::allocate<Vanetza_Security_EtsiTs103097Data_t>();
        signed_data->tbsData->payload->data = inner_data;
        inner_data->protocolVersion = 3;
        inner_data->content = asn1::allocate<Vanetza_Security_Ieee1609Dot2Content_t>();
        inner_data->content->present = Vanetza_Security_Ieee1609Dot2Content_PR_unsecuredData;
        OCTET_STRING_fromBuf(&inner_data->content->choice.unsecuredData,
            reinterpret_cast<const char*>(inner_bytes.data()), inner_bytes.size());

        signed_data->signature.present = Vanetza_Security_Signature_PR_ecdsaNistP256Signature;
        signed_data->signature.choice.ecdsaNistP256Signature.rSig.present =
            Vanetza_Security_EccP256CurvePoint_PR_x_only;
        std::array<std::uint8_t, 32> zeros {};
        OCTET_STRING_fromBuf(&signed_data->signature.choice.ecdsaNistP256Signature.rSig.choice.x_only,
            reinterpret_cast<const char*>(zeros.data()), zeros.size());
        OCTET_STRING_fromBuf(&signed_data->signature.choice.ecdsaNistP256Signature.sSig,
            reinterpret_cast<const char*>(zeros.data()), zeros.size());

        ByteBuffer outer_bytes = outer.encode();
        CertificateTrustList ctl;
        if (!ctl.decode(outer_bytes)) {
            throw std::runtime_error("CTL test fixture: outer message could not be decoded");
        }
        return ctl;
    }

private:
    static void populate_stub_cert(Vanetza_Security_EtsiTs103097Certificate_t& cert, const PublicKey& key,
        const char* name)
    {
        cert.version = 3;
        cert.type = Vanetza_Security_CertificateType_explicit;
        cert.issuer.present = Vanetza_Security_IssuerIdentifier_PR_self;
        cert.issuer.choice.self = Vanetza_Security_HashAlgorithm_sha256;

        auto& tbs = cert.toBeSigned;
        tbs.id.present = Vanetza_Security_CertificateId_PR_name;
        OCTET_STRING_fromBuf(&tbs.id.choice.name, name, std::strlen(name));
        tbs.cracaId.buf = static_cast<std::uint8_t*>(std::calloc(3, 1));
        tbs.cracaId.size = 3;
        tbs.crlSeries = 0;
        tbs.validityPeriod.start = security::v3::convert_time32(Clock::time_point {});
        tbs.validityPeriod.duration.present = Vanetza_Security_Duration_PR_hours;
        tbs.validityPeriod.duration.choice.hours = 24;
        tbs.verifyKeyIndicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
        set_verification_key(tbs.verifyKeyIndicator.choice.verificationKey, key);
    }

    HashedId8 m_issuer;
    asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data_t> m_data { asn_DEF_Vanetza_Security_EtsiTs102941Data };
};

inline HashedId8 make_id(std::uint8_t fill)
{
    HashedId8 id;
    id.octets.fill(fill);
    return id;
}

// Builds a TLM-signed CTL message (ECTL). Mirrors TestRcaCtlBuilder but for
// the certificateTrustListTlm variant; entries are RootCaEntry / TlmEntry / DcEntry.
class TestTlmCtlBuilder
{
public:
    TestTlmCtlBuilder(const HashedId8& issuer, bool is_full, std::uint8_t sequence) : m_issuer(issuer)
    {
        m_data->version = 1;
        m_data->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_certificateTrustListTlm;
        auto& format = m_data->content.choice.certificateTrustListTlm;
        format.version = 1;
        format.nextUpdate = 0;
        format.isFullCtl = is_full ? 1 : 0;
        format.ctlSequence = sequence;
    }

    TestTlmCtlBuilder& add_root_ca(const PublicKey& key)
    {
        auto* cmd = asn1::allocate<Vanetza_Security_CtlCommand_t>();
        cmd->present = Vanetza_Security_CtlCommand_PR_add;
        cmd->choice.add.present = Vanetza_Security_CtlEntry_PR_rca;
        auto& rca = cmd->choice.add.choice.rca;
        // Name matches build_stub_certificate so tests can derive the same HashedId8.
        populate_stub_cert(rca.selfsignedRootCa, key, "test-cert");
        asn_sequence_add(&m_data->content.choice.certificateTrustListTlm.ctlCommands, cmd);
        return *this;
    }

    TestTlmCtlBuilder& add_tlm(const PublicKey& key, const std::string& cpoc_url)
    {
        auto* cmd = asn1::allocate<Vanetza_Security_CtlCommand_t>();
        cmd->present = Vanetza_Security_CtlCommand_PR_add;
        cmd->choice.add.present = Vanetza_Security_CtlEntry_PR_tlm;
        auto& tlm = cmd->choice.add.choice.tlm;
        populate_stub_cert(tlm.selfSignedTLMCertificate, key, "test-cert");
        OCTET_STRING_fromBuf(&tlm.accessPoint, cpoc_url.data(), cpoc_url.size());
        asn_sequence_add(&m_data->content.choice.certificateTrustListTlm.ctlCommands, cmd);
        return *this;
    }

    TestTlmCtlBuilder& delete_cert(const HashedId8& id)
    {
        auto* cmd = asn1::allocate<Vanetza_Security_CtlCommand_t>();
        cmd->present = Vanetza_Security_CtlCommand_PR_delete;
        cmd->choice.Delete.present = Vanetza_Security_CtlDelete_PR_cert;
        OCTET_STRING_fromBuf(&cmd->choice.Delete.choice.cert, reinterpret_cast<const char*>(id.octets.data()),
            id.octets.size());
        asn_sequence_add(&m_data->content.choice.certificateTrustListTlm.ctlCommands, cmd);
        return *this;
    }

    CertificateTrustList build()
    {
        ByteBuffer inner_bytes = m_data.encode();

        asn1::asn1c_oer_wrapper<Vanetza_Security_TlmCertificateTrustListMessage_t>
            outer(asn_DEF_Vanetza_Security_TlmCertificateTrustListMessage);
        outer->protocolVersion = 3;
        outer->content = asn1::allocate<Vanetza_Security_Ieee1609Dot2Content_t>();
        outer->content->present = Vanetza_Security_Ieee1609Dot2Content_PR_signedData;

        auto* signed_data = asn1::allocate<Vanetza_Security_SignedData_t>();
        outer->content->choice.signedData = signed_data;
        signed_data->hashId = Vanetza_Security_HashAlgorithm_sha256;

        signed_data->signer.present = Vanetza_Security_SignerIdentifier_PR_digest;
        OCTET_STRING_fromBuf(&signed_data->signer.choice.digest, reinterpret_cast<const char*>(m_issuer.octets.data()),
            m_issuer.octets.size());

        signed_data->tbsData = asn1::allocate<Vanetza_Security_ToBeSignedData_t>();
        signed_data->tbsData->headerInfo.psid = aid::CTL;
        signed_data->tbsData->payload = asn1::allocate<Vanetza_Security_SignedDataPayload_t>();
        auto* inner_data = asn1::allocate<Vanetza_Security_EtsiTs103097Data_t>();
        signed_data->tbsData->payload->data = inner_data;
        inner_data->protocolVersion = 3;
        inner_data->content = asn1::allocate<Vanetza_Security_Ieee1609Dot2Content_t>();
        inner_data->content->present = Vanetza_Security_Ieee1609Dot2Content_PR_unsecuredData;
        OCTET_STRING_fromBuf(&inner_data->content->choice.unsecuredData,
            reinterpret_cast<const char*>(inner_bytes.data()), inner_bytes.size());

        signed_data->signature.present = Vanetza_Security_Signature_PR_ecdsaNistP256Signature;
        signed_data->signature.choice.ecdsaNistP256Signature.rSig.present =
            Vanetza_Security_EccP256CurvePoint_PR_x_only;
        std::array<std::uint8_t, 32> zeros {};
        OCTET_STRING_fromBuf(&signed_data->signature.choice.ecdsaNistP256Signature.rSig.choice.x_only,
            reinterpret_cast<const char*>(zeros.data()), zeros.size());
        OCTET_STRING_fromBuf(&signed_data->signature.choice.ecdsaNistP256Signature.sSig,
            reinterpret_cast<const char*>(zeros.data()), zeros.size());

        ByteBuffer outer_bytes = outer.encode();
        CertificateTrustList ctl;
        if (!ctl.decode(outer_bytes)) {
            throw std::runtime_error("TLM CTL test fixture: outer message could not be decoded");
        }
        return ctl;
    }

private:
    static void populate_stub_cert(Vanetza_Security_EtsiTs103097Certificate_t& cert, const PublicKey& key,
        const char* name)
    {
        cert.version = 3;
        cert.type = Vanetza_Security_CertificateType_explicit;
        cert.issuer.present = Vanetza_Security_IssuerIdentifier_PR_self;
        cert.issuer.choice.self = Vanetza_Security_HashAlgorithm_sha256;

        auto& tbs = cert.toBeSigned;
        tbs.id.present = Vanetza_Security_CertificateId_PR_name;
        OCTET_STRING_fromBuf(&tbs.id.choice.name, name, std::strlen(name));
        tbs.cracaId.buf = static_cast<std::uint8_t*>(std::calloc(3, 1));
        tbs.cracaId.size = 3;
        tbs.crlSeries = 0;
        tbs.validityPeriod.start = security::v3::convert_time32(Clock::time_point {});
        tbs.validityPeriod.duration.present = Vanetza_Security_Duration_PR_hours;
        tbs.validityPeriod.duration.choice.hours = 24;
        tbs.verifyKeyIndicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
        set_verification_key(tbs.verifyKeyIndicator.choice.verificationKey, key);
    }

    HashedId8 m_issuer;
    asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data_t> m_data { asn_DEF_Vanetza_Security_EtsiTs102941Data };
};

} // namespace pki
} // namespace vanetza

#include "certificate_trust_list.hpp"
#include "asn1.hpp"
#include "certificate.hpp"
#include "certificate_storage.hpp"
#include "exception.hpp"
#include "filesystem.hpp"
#include "hexstring.hpp"
#include "trust_list_storage.hpp"
#include "validation.hpp"
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <iostream>

namespace vanetza
{
namespace pki
{

CertificateTrustList::CertificateTrustList() : m_asn1(asn_DEF_Vanetza_Security_TlmCertificateTrustListMessage)
{
}

bool CertificateTrustList::decode(const std::string& buffer)
{
    return m_asn1.decode(buffer.data(), buffer.size());
}

bool CertificateTrustList::decode(const ByteBuffer& buffer)
{
    return m_asn1.decode(buffer.data(), buffer.size());
}

ByteBuffer CertificateTrustList::encode() const
{
    return m_asn1.encode();
}

CertificateTrustList CertificateTrustList::from_file(const std::filesystem::path& path)
{
    ByteBuffer buffer = read(path);
    if (buffer.empty()) {
        throw DecodingFailure("trust list file is empty or missing");
    }

    CertificateTrustList ctl;
    if (!ctl.decode(buffer)) {
        throw DecodingFailure("trust list message could not be decoded");
    }
    return ctl;
}

namespace
{

const OCTET_STRING_t& require_signed_payload(const Vanetza_Security_EtsiTs103097Data_t& msg)
{
    const OCTET_STRING_t* opaque = get_signed_payload(msg.content);
    if (!opaque) {
        throw DecodingFailure("cannot access signed payload of trust list message");
    }
    return *opaque;
}

template<class Commands> void dispatch_ctl_commands(const Commands& commands, CtlVisitor& visitor)
{
    for (int i = 0; i < commands.list.count; ++i) {
        const Vanetza_Security_CtlCommand_t* cmd = commands.list.array[i];
        if (!cmd) {
            continue;
        } else if (cmd->present == Vanetza_Security_CtlCommand_PR_add) {
            const Vanetza_Security_CtlEntry_t& entry = cmd->choice.add;
            switch (entry.present) {
                case Vanetza_Security_CtlEntry_PR_rca:
                    visitor.add_root_ca(entry.choice.rca);
                    break;
                case Vanetza_Security_CtlEntry_PR_tlm:
                    visitor.add_trust_list_manager(entry.choice.tlm);
                    break;
                case Vanetza_Security_CtlEntry_PR_dc:
                    visitor.add_distribution_centre(entry.choice.dc);
                    break;
                case Vanetza_Security_CtlEntry_PR_aa:
                    visitor.add_authorization_authority(entry.choice.aa);
                    break;
                case Vanetza_Security_CtlEntry_PR_ea:
                    visitor.add_enrolment_authority(entry.choice.ea);
                    break;
                default:
                    break;
            }
        } else if (cmd->present == Vanetza_Security_CtlCommand_PR_delete) {
            const Vanetza_Security_CtlDelete_t& del = cmd->choice.Delete;
            switch (del.present) {
                case Vanetza_Security_CtlDelete_PR_cert:
                    visitor.remove_certificate(del.choice.cert);
                    break;
                case Vanetza_Security_CtlDelete_PR_dc:
                    visitor.remove_distribution_centre(del.choice.dc);
                    break;
                default:
                    break;
            }
        }
    }
}

const Vanetza_Security_CtlFormat_t* find_ctl_format(const Vanetza_Security_EtsiTs102941Data_t& mgmt)
{
    switch (mgmt.content.present) {
        case Vanetza_Security_EtsiTs102941DataContent_PR_certificateTrustListRca:
            return &mgmt.content.choice.certificateTrustListRca;
        case Vanetza_Security_EtsiTs102941DataContent_PR_certificateTrustListTlm:
            return &mgmt.content.choice.certificateTrustListTlm;
        default:
            return nullptr;
    }
}

} // namespace

void CertificateTrustList::visit_tlm_ctl(CtlVisitor& visitor) const
{
    auto mgmt = TlmCtlData::from_opaque(require_signed_payload(*m_asn1));
    dispatch_ctl_commands(mgmt->content.choice.certificateTrustListTlm.ctlCommands, visitor);
}

void CertificateTrustList::visit_rca_ctl(CtlVisitor& visitor) const
{
    auto mgmt = RcaCtlData::from_opaque(require_signed_payload(*m_asn1));
    dispatch_ctl_commands(mgmt->content.choice.certificateTrustListRca.ctlCommands, visitor);
}

boost::optional<bool> CertificateTrustList::is_full_ctl() const
{
    const OCTET_STRING_t* opaque = get_signed_payload(raw().content);
    if (!opaque) {
        return boost::none;
    }
    MgmtData mgmt;
    if (!mgmt.decode(*opaque)) {
        return boost::none;
    }
    const Vanetza_Security_CtlFormat_t* format = find_ctl_format(*mgmt);
    if (!format) {
        return boost::none;
    }
    return format->isFullCtl != 0;
}

boost::optional<std::uint8_t> CertificateTrustList::ctl_sequence() const
{
    const OCTET_STRING_t* opaque = get_signed_payload(raw().content);
    if (!opaque) {
        return boost::none;
    }
    MgmtData mgmt;
    if (!mgmt.decode(*opaque)) {
        return boost::none;
    }
    const Vanetza_Security_CtlFormat_t* format = find_ctl_format(*mgmt);
    if (!format) {
        return boost::none;
    }
    return static_cast<std::uint8_t>(format->ctlSequence);
}

void CertificateTrustList::print() const
{
    xer_fprint(stdout, &asn_DEF_Vanetza_Security_TlmCertificateTrustListMessage, &*m_asn1);
}

boost::optional<HashedId8> CertificateTrustList::get_hashed_id8(SecurityModule& security) const
{
    const Vanetza_Security_SignedData_t* signed_data = get_signed_data(raw());
    if (signed_data) {
        switch (signed_data->signer.present) {
            case Vanetza_Security_SignerIdentifier_PR_digest:
                return HashedId8::from_buffer(signed_data->signer.choice.digest);
            case Vanetza_Security_SignerIdentifier_PR_certificate: {
                const Vanetza_Security_SequenceOfCertificate_t& certs = signed_data->signer.choice.certificate;
                if (certs.list.count == 1 && certs.list.array[0]) {
                    return calculate_hashed_id8(security, *certs.list.array[0]);
                }
            } break;
            default:
                break;
        }
    }

    return boost::none;
}

CertificateTrustListProcessor::CertificateTrustListProcessor(std::shared_ptr<SecurityModule> security) :
    m_security(security)
{
}

void CertificateTrustListProcessor::process(const CertificateTrustList& ctl)
{
    const Vanetza_Security_Opaque_t* payload = get_signed_payload(ctl.raw().content);
    boost::optional<HashedId8> ctl_signer = ctl.get_hashed_id8(*m_security);
    if (!payload || !ctl_signer) {
        return;
    }

    MgmtData mgmt;
    if (!mgmt.decode(*payload)) {
        return;
    }

    const Vanetza_Security_CtlFormat_t* format = find_ctl_format(*mgmt);
    if (!format) {
        return;
    }

    // Per TS 102 941 v1.4.1 §6.3.4: a full CTL is the complete trust state.
    // Drop everything before applying so entries absent from the new full list
    // don't linger. This is correct under the single-CTL-chain contract on this
    // processor (one instance per issuer; see class comment).
    if (format->isFullCtl) {
        m_enrolment_authorities.clear();
        m_authorization_authorities.clear();
        m_distribution_centres.clear();
        m_root_cas.clear();
        m_trust_list_managers.clear();
    }
    for (int i = 0; i < format->ctlCommands.list.count; ++i) {
        this->process(*format->ctlCommands.list.array[i], *ctl_signer);
    }
}

void CertificateTrustListProcessor::process(const Vanetza_Security_CtlCommand_t& cmd, const HashedId8& ctl_signer)
{
    switch (cmd.present) {
        case Vanetza_Security_CtlCommand_PR_add:
            add(cmd.choice.add, ctl_signer);
            break;
        case Vanetza_Security_CtlCommand_PR_delete:
            remove(cmd.choice.Delete);
            break;
        default:
            // no op
            break;
    }
}

void CertificateTrustListProcessor::add(const Vanetza_Security_CtlEntry_t& entry, const HashedId8& ctl_signer)
{
    switch (entry.present) {
        case Vanetza_Security_CtlEntry_PR_aa:
            add_authorization_authority(entry.choice.aa, ctl_signer);
            break;
        case Vanetza_Security_CtlEntry_PR_ea:
            add_enrolment_authority(entry.choice.ea, ctl_signer);
            break;
        case Vanetza_Security_CtlEntry_PR_dc:
            add_distribution_centre(entry.choice.dc);
            break;
        case Vanetza_Security_CtlEntry_PR_rca:
            add_root_ca(entry.choice.rca);
            break;
        case Vanetza_Security_CtlEntry_PR_tlm:
            add_trust_list_manager(entry.choice.tlm);
            break;
        default:
            // no op
            break;
    }
}

void CertificateTrustListProcessor::remove(const Vanetza_Security_CtlDelete_t& removal)
{
    switch (removal.present) {
        case Vanetza_Security_CtlDelete_PR_cert:
            remove_certificate(removal.choice.cert);
            break;
        case Vanetza_Security_CtlDelete_PR_dc:
            remove_dc(removal.choice.dc);
            break;
        default:
            // no op
            break;
    }
}

void CertificateTrustListProcessor::add_root_ca(const Vanetza_Security_RootCaEntry_t& rca)
{
    // The RCA's self-signed certificate is the trust anchor; key by its own HashedId8.
    // The optional successorTo backlink (TS 102 941 v1.4.1 §6.3.4) is informational and
    // ignored here — see [[gap-link-certificates]] for the rollover mechanism.
    Certificate cert(rca.selfsignedRootCa);
    HashedId8 hid = cert.calculate_hashed_id8(*m_security);
    m_root_cas.insert_or_assign(hid, std::move(cert));
}

void CertificateTrustListProcessor::add_authorization_authority(const Vanetza_Security_AaEntry_t& entry,
    const HashedId8& ctl_signer)
{
    AuthorizationAuthority aa;
    aa.access_point.assign(reinterpret_cast<const char*>(entry.accessPoint.buf), entry.accessPoint.size);
    aa.certificate = Certificate(entry.aaCertificate);
    m_authorization_authorities.insert_or_assign(ctl_signer, std::move(aa));
}

void CertificateTrustListProcessor::add_enrolment_authority(const Vanetza_Security_EaEntry_t& entry,
    const HashedId8& ctl_signer)
{
    EnrolmentAuthority ea;
    ea.aa_access_point.assign(reinterpret_cast<const char*>(entry.aaAccessPoint.buf), entry.aaAccessPoint.size);
    if (entry.itsAccessPoint) {
        auto buf = reinterpret_cast<const char*>(entry.itsAccessPoint->buf);
        ea.its_access_point.assign(buf, entry.itsAccessPoint->size);
    }
    ea.certificate = Certificate(entry.eaCertificate);
    m_enrolment_authorities.insert_or_assign(ctl_signer, std::move(ea));
}

void CertificateTrustListProcessor::add_distribution_centre(const Vanetza_Security_DcEntry_t& dc)
{
    std::string url(reinterpret_cast<const char*>(dc.url.buf), dc.url.size);
    for (int i = 0; i < dc.cert.list.count; ++i) {
        const Vanetza_Security_HashedId8_t* cert = dc.cert.list.array[i];
        if (!cert) {
            continue;
        }
        if (auto hid = HashedId8::from_buffer(*cert)) {
            m_distribution_centres.insert_or_assign(*hid, url);
        }
    }
}

void CertificateTrustListProcessor::add_trust_list_manager(const Vanetza_Security_TlmEntry_t& tlm)
{
    // CPOC access point (tlm.accessPoint) not tracked here; add a parallel map if callers need it.
    Certificate cert(tlm.selfSignedTLMCertificate);
    HashedId8 hid = cert.calculate_hashed_id8(*m_security);
    m_trust_list_managers.insert_or_assign(hid, std::move(cert));
}

void CertificateTrustListProcessor::remove_certificate(const Vanetza_Security_HashedId8_t& id)
{
    HashedId8 hid;
    hid.octets = security::v3::convert(id);
    m_enrolment_authorities.erase(hid);
    m_authorization_authorities.erase(hid);
    m_distribution_centres.erase(hid);
    m_root_cas.erase(hid);
    m_trust_list_managers.erase(hid);
}

void CertificateTrustListProcessor::remove_dc(const Vanetza_Security_Url_t& url)
{
    std::string target(reinterpret_cast<const char*>(url.buf), url.size);
    for (auto it = m_distribution_centres.begin(); it != m_distribution_centres.end();) {
        if (it->second == target) {
            it = m_distribution_centres.erase(it);
        } else {
            ++it;
        }
    }
}

boost::optional<EnrolmentAuthority>
CertificateTrustListProcessor::get_enrolment_authority(const HashedId8& root_ca) const
{
    auto found = m_enrolment_authorities.find(root_ca);
    if (found != m_enrolment_authorities.end()) {
        return found->second;
    } else {
        return boost::none;
    }
}

boost::optional<AuthorizationAuthority>
CertificateTrustListProcessor::get_authorization_authority(const HashedId8& root_ca) const
{
    auto found = m_authorization_authorities.find(root_ca);
    if (found != m_authorization_authorities.end()) {
        return found->second;
    } else {
        return boost::none;
    }
}

boost::optional<Certificate> CertificateTrustListProcessor::get_root_ca(const HashedId8& digest) const
{
    auto found = m_root_cas.find(digest);
    if (found != m_root_cas.end()) {
        return found->second;
    }
    return boost::none;
}

boost::optional<Certificate> CertificateTrustListProcessor::get_trust_list_manager(const HashedId8& digest) const
{
    auto found = m_trust_list_managers.find(digest);
    if (found != m_trust_list_managers.end()) {
        return found->second;
    }
    return boost::none;
}

boost::optional<std::string> CertificateTrustListProcessor::get_distribution_centre(const HashedId8& cert_digest) const
{
    auto found = m_distribution_centres.find(cert_digest);
    if (found != m_distribution_centres.end()) {
        return found->second;
    }
    return boost::none;
}

namespace
{

std::string build_ctl_name(SecurityModule& security, const Vanetza_Security_EtsiTs103097Certificate_t& cert)
{
    auto name = get_name(cert);
    auto hid8 = hexstring(calculate_hashed_id8(security, cert));
    if (name.empty()) {
        return "<HashedId8:" + hid8 + ">";
    } else {
        return name + " (" + hid8 + ")";
    }
}

} // namespace

void CtlListingVisitor::add_root_ca(const Vanetza_Security_RootCaEntry_t& rca)
{
    std::cout << "- Root CA: " << build_ctl_name(m_security, rca.selfsignedRootCa) << "\n";
    Certificate root_ca_cert { rca.selfsignedRootCa };
    std::cout << "|-> valid: from " << Clock::at(root_ca_cert.valid_since()) << " until "
              << Clock::at(root_ca_cert.valid_until()) << "\n";
}

void CtlListingVisitor::add_trust_list_manager(const Vanetza_Security_TlmEntry_t& tlm)
{
    std::cout << "- TLM: " << build_ctl_name(m_security, tlm.selfSignedTLMCertificate) << "\n";
    std::cout << "|-> access point: " << to_string(tlm.accessPoint) << "\n";
}

void CtlListingVisitor::add_distribution_centre(const Vanetza_Security_DcEntry_t& dc)
{
    std::cout << "- DC: " << to_string(dc.url) << "\n";
    for (int i = 0; i < dc.cert.list.count; ++i) {
        auto digest = security::v3::convert(*dc.cert.list.array[i]);
        std::cout << "|-> for Root CA " << hexstring(digest) << "\n";
    }
}

void CtlListingVisitor::add_authorization_authority(const Vanetza_Security_AaEntry_t& aa)
{
    std::cout << "- AA: " << to_string(aa.accessPoint) << "\n";
}

void CtlListingVisitor::add_enrolment_authority(const Vanetza_Security_EaEntry_t& ea)
{
    std::cout << "- EA: " << to_string(ea.aaAccessPoint) << " [AA]\n";
    if (ea.itsAccessPoint) {
        std::cout << "- EA: " << to_string(*ea.itsAccessPoint) << " [ITS]\n";
    }
}

CertificateExportVisitor::CertificateExportVisitor(
    std::shared_ptr<CertificateStorage> aa, std::shared_ptr<CertificateStorage> ea)
    : m_aa(std::move(aa)), m_ea(std::move(ea))
{
}

void CertificateExportVisitor::add_authorization_authority(const Vanetza_Security_AaEntry_t& entry)
{
    if (m_aa) {
        m_aa->store(Certificate(entry.aaCertificate));
        ++m_exported_aa;
    }
}

void CertificateExportVisitor::add_enrolment_authority(const Vanetza_Security_EaEntry_t& entry)
{
    if (m_ea) {
        m_ea->store(Certificate(entry.eaCertificate));
        ++m_exported_ea;
    }
}

CertificateTrustListProcessor process_stored_ctl(const TrustListStorage& trust_lists,
    std::shared_ptr<SecurityModule> security, const HashedId8& root_ca)
{
    auto maybe_ctl = trust_lists.fetch(root_ca);
    if (!maybe_ctl) {
        throw UsageError("no CTL is in store for the current Root CA", "fetch a CTL via 'dc fetch ctl'");
    }
    CertificateTrustListProcessor processor(std::move(security));
    processor.process(*maybe_ctl);
    return processor;
}

EnrolmentAuthority require_enrolment_authority(const CertificateTrustListProcessor& processor, const HashedId8& root_ca)
{
    auto maybe_ea = processor.get_enrolment_authority(root_ca);
    if (!maybe_ea) {
        throw UsageError("no Enrolment Authority is known for the current Root CA", "fetch a fresh CTL");
    }
    if (!maybe_ea->certificate.get_encryption_key()) {
        throw DecodingFailure("missing encryption key in EA certificate");
    }
    return std::move(*maybe_ea);
}

AuthorizationAuthority require_authorization_authority(const CertificateTrustListProcessor& processor,
    const HashedId8& root_ca)
{
    auto maybe_aa = processor.get_authorization_authority(root_ca);
    if (!maybe_aa) {
        throw UsageError("no Authorization Authority is known for the current Root CA", "fetch a fresh CTL");
    }
    if (!maybe_aa->certificate.get_encryption_key()) {
        throw DecodingFailure("missing encryption key in AA certificate");
    }
    return std::move(*maybe_aa);
}

} // namespace pki
} // namespace vanetza

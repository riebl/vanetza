#pragma once

#include "certificate.hpp"
#include "hashed_id8.hpp"
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/CtlCommand.h>
#include <vanetza/asn1/security/TlmCertificateTrustListMessage.h>
#include <boost/optional/optional.hpp>
#include <cstdint>
#include <filesystem>
#include <map>
#include <string>

namespace vanetza
{
namespace pki
{

// forward declarations
class Certificate;
class SecurityModule;
class TrustListStorage;

/// \brief Visitor for the entries of a TLM certificate trust list.
class CtlVisitor
{
public:
    virtual ~CtlVisitor() = default;

    // add commands
    virtual void add_root_ca(const Vanetza_Security_RootCaEntry_t&)
    {
    }

    virtual void add_trust_list_manager(const Vanetza_Security_TlmEntry_t&)
    {
    }

    virtual void add_distribution_centre(const Vanetza_Security_DcEntry_t&)
    {
    }

    virtual void add_authorization_authority(const Vanetza_Security_AaEntry_t&)
    {
    }

    virtual void add_enrolment_authority(const Vanetza_Security_EaEntry_t&)
    {
    }

    // delete commands
    virtual void remove_certificate(const Vanetza_Security_HashedId8_t&)
    {
    }

    virtual void remove_distribution_centre(const Vanetza_Security_Url_t&)
    {
    }
};

/**
 * \brief Prints CTL entries to stdout as a human-readable tree.
 *
 * Works for both RCA CTLs (visit_rca_ctl) and TLM CTLs/ECTLs (visit_tlm_ctl).
 */ 
class CtlListingVisitor : public CtlVisitor
{
public:
    explicit CtlListingVisitor(SecurityModule& security) : m_security(security)
    {
    }

    void add_root_ca(const Vanetza_Security_RootCaEntry_t&) override;
    void add_trust_list_manager(const Vanetza_Security_TlmEntry_t&) override;
    void add_distribution_centre(const Vanetza_Security_DcEntry_t&) override;
    void add_authorization_authority(const Vanetza_Security_AaEntry_t&) override;
    void add_enrolment_authority(const Vanetza_Security_EaEntry_t&) override;

private:
    SecurityModule& m_security;
};

class CertificateTrustList
{
public:
    CertificateTrustList();
    bool decode(const std::string&);
    bool decode(const ByteBuffer&);
    ByteBuffer encode() const;

    /**
     * Read the OER-encoded trust list message from a file and decode it.
     *
     * \throws DecodingFailure if the file is empty or decoding fails
     */
    static CertificateTrustList from_file(const std::filesystem::path&);

    boost::optional<HashedId8> get_hashed_id8(SecurityModule&) const;

    /**
     * Per TS 102 941 v1.4.1 §6.3.4: full CTL carries the complete trust state
     * (only add commands); delta CTL carries changes (adds + deletes) on top of
     * the previous full list with ctlSequence one less than this one.
     *
     * Returns boost::none if the inner CtlFormat cannot be decoded.
     */
    boost::optional<bool> is_full_ctl() const;
    boost::optional<std::uint8_t> ctl_sequence() const;

    /**
     * Iterate the TLM certificate trust list entries through `visitor`.
     *
     * \throws DecodingFailure on missing payload, malformed management data,
     *         or content that is not a TLM certificate trust list
     */
    void visit_tlm_ctl(CtlVisitor&) const;

    // Same as visit_tlm_ctl but for RCA certificate trust lists.
    void visit_rca_ctl(CtlVisitor&) const;

    void print() const;

    const Vanetza_Security_EtsiTs103097Data_t& raw() const
    {
        return *m_asn1;
    }

private:
    asn1::asn1c_oer_wrapper<Vanetza_Security_TlmCertificateTrustListMessage_t> m_asn1;
};

struct EnrolmentAuthority
{
    Certificate certificate;
    std::string aa_access_point;
    std::string its_access_point;
};

struct AuthorizationAuthority
{
    Certificate certificate;
    std::string access_point;
};

/**
 * \brief Decoded view of a CertificateTrustList's commands.
 *
 * One instance processes a single CTL chain — either (full, delta, delta, ...)
 * from one RCA, or the same from one TLM. Mixing issuers (e.g. an RCA CTL and
 * an ECTL) on the same instance is unsupported: a full CTL clears all state,
 * so later content from a different issuer would silently wipe earlier content.
 * Build a fresh processor per chain.
 */
class CertificateTrustListProcessor
{
public:
    CertificateTrustListProcessor(std::shared_ptr<SecurityModule>);
    void process(const CertificateTrustList&);

    boost::optional<EnrolmentAuthority> get_enrolment_authority(const HashedId8&) const;
    boost::optional<AuthorizationAuthority> get_authorization_authority(const HashedId8&) const;
    boost::optional<Certificate> get_root_ca(const HashedId8&) const;
    boost::optional<Certificate> get_trust_list_manager(const HashedId8&) const;
    boost::optional<std::string> get_distribution_centre(const HashedId8&) const;

protected:
    void process(const Vanetza_Security_CtlCommand_t&, const HashedId8& ctl_signer);
    void add(const Vanetza_Security_CtlEntry_t&, const HashedId8& ctl_signer);
    void remove(const Vanetza_Security_CtlDelete_t&);

    void add_root_ca(const Vanetza_Security_RootCaEntry_t&);
    void add_authorization_authority(const Vanetza_Security_AaEntry_t&, const HashedId8& ctl_signer); // signer = issuing RCA, key for AA map
    void add_enrolment_authority(const Vanetza_Security_EaEntry_t&, const HashedId8& ctl_signer); // signer = issuing RCA, key for EA map
    void add_distribution_centre(const Vanetza_Security_DcEntry_t&);
    void add_trust_list_manager(const Vanetza_Security_TlmEntry_t&);

    void remove_certificate(const Vanetza_Security_HashedId8_t&);
    void remove_dc(const Vanetza_Security_Url_t&);

private:
    std::shared_ptr<SecurityModule> m_security;
    std::map<HashedId8, EnrolmentAuthority> m_enrolment_authorities;
    std::map<HashedId8, AuthorizationAuthority> m_authorization_authorities;
    std::map<HashedId8, std::string> m_distribution_centres;
    std::map<HashedId8, Certificate> m_root_cas;
    std::map<HashedId8, Certificate> m_trust_list_managers;
};

/**
 * Fetch and process the stored CTL for `root_ca`.
 *
 * \throws UsageError if no CTL is stored for `root_ca`
 */
CertificateTrustListProcessor process_stored_ctl(const TrustListStorage& trust_lists,
    std::shared_ptr<SecurityModule> security, const HashedId8& root_ca);

// Require the EA/AA for `root_ca` to be listed and carry an encryption key.
EnrolmentAuthority require_enrolment_authority(const CertificateTrustListProcessor&, const HashedId8& root_ca);
AuthorizationAuthority require_authorization_authority(const CertificateTrustListProcessor&, const HashedId8& root_ca);

} // namespace pki
} // namespace vanetza

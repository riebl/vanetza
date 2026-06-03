#pragma once

#include "hashed_id8.hpp"
#include "keys.hpp"
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/Certificate.h>
#include <vanetza/asn1/security/EtsiTs103097Certificate.h>
#include <vanetza/common/clock.hpp>

// asn1c quirk: complete the struct tags it forward-declares but never defines.
struct Vanetza_Security_Certificate : Vanetza_Security_CertificateBase
{
};

struct Vanetza_Security_EtsiTs103097Certificate : Vanetza_Security_ExplicitCertificate_t
{
};

namespace vanetza
{
namespace pki
{

class SecurityModule;

class Certificate
{
public:
    Certificate();
    explicit Certificate(const Vanetza_Security_EtsiTs103097Certificate_t&);

    HashedId8 calculate_hashed_id8(SecurityModule&) const;
    bool is_canonical() const;
    std::string get_name() const;
    PublicKey get_public_key() const;
    Clock::time_point valid_since() const;
    Clock::time_point valid_until() const;
    boost::optional<PublicKey> get_encryption_key() const;

    bool decode(const char* data, std::size_t length);
    bool decode(const std::string&);
    bool decode(const ByteBuffer&);
    ByteBuffer encode() const;

    const Vanetza_Security_EtsiTs103097Certificate_t& raw() const
    {
        return *m_asn1;
    }

    void print() const;

private:
    vanetza::asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs103097Certificate_t> m_asn1;
};

bool is_currently_valid(const Certificate&, Clock::time_point);

/**
 * Check if certificate is a compliant Root CA certificate.
 * Rules are given by section 7.3.2 in TS 103 097 V1.3.1
 *
 * \param cert
 * \return true if certificate complies
 */
bool is_root_ca(const Certificate&);

// PKI role inferred from issuer, permissions and CertificateId per TS 103 097 V2.1.1 §7.2.
enum class CertificateRole
{
    RootCa, // §7.2.3: self-issued CA
    EnrolmentAuthority, // §7.2.4: sub-CA whose issuing scope grants SCR
    AuthorizationAuthority, // §7.2.4: sub-CA whose issuing scope grants services
    EnrolmentCredential, // §7.2.2: end entity with CertificateId name
    AuthorizationTicket, // §7.2.1: end entity with CertificateId none
    Tlm, // §7.2.5: self-issued, signs CTL, no certIssuePermissions
    Unknown, // matches no profile above
};

// Classify the certificate's PKI role. Never throws.
CertificateRole certificate_role(const Certificate&);

Sha256Hash calculate_sha256_hash(SecurityModule&, const Certificate&);
Sha384Hash calculate_sha384_hash(SecurityModule&, const Certificate&);
Sha256Hash calculate_sha256_hash(SecurityModule&, const Vanetza_Security_Certificate_t&);
Sha384Hash calculate_sha384_hash(SecurityModule&, const Vanetza_Security_Certificate_t&);
HashedId8 calculate_hashed_id8(SecurityModule&, const Vanetza_Security_Certificate_t&);
PublicKey get_public_key(const Vanetza_Security_Certificate_t&);
std::string get_name(const Vanetza_Security_Certificate_t&);
bool is_canonical(const Vanetza_Security_Certificate_t&);

} // namespace pki
} // namespace vanetza

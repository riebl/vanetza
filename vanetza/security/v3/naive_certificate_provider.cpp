#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/v3/naive_certificate_provider.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

NaiveCertificateProvider::NaiveCertificateProvider(const Runtime& rt) :
    m_runtime(rt),
    m_own_key_pair(m_crypto_backend.generate_key_pair()),
    m_own_certificate(generate_authorization_ticket()) { }

const Certificate& NaiveCertificateProvider::own_certificate()
{
    // Implement the renewal
    return m_own_certificate;
}

std::list<Certificate> NaiveCertificateProvider::own_chain()
{
    static const std::list<Certificate> chain = { aa_certificate() };

    return chain;
}

const ecdsa256::PrivateKey& NaiveCertificateProvider::own_private_key()
{
    return m_own_key_pair.private_key;
}

const ecdsa256::KeyPair& NaiveCertificateProvider::aa_key_pair()
{
    static const ecdsa256::KeyPair aa_key_pair = m_crypto_backend.generate_key_pair();

    return aa_key_pair;
}

const ecdsa256::KeyPair& NaiveCertificateProvider::root_key_pair()
{
    static const ecdsa256::KeyPair root_key_pair = m_crypto_backend.generate_key_pair();

    return root_key_pair;
}

const Certificate& NaiveCertificateProvider::aa_certificate()
{
    static const std::string aa_subject("Naive Authorization CA");
    static const Certificate aa_certificate = generate_aa_certificate(aa_subject);

    return aa_certificate;
}

const Certificate& NaiveCertificateProvider::root_certificate()
{
    static const std::string root_subject("Naive Root CA");
    static const Certificate root_certificate = generate_root_certificate(root_subject);

    return root_certificate;
}

Certificate NaiveCertificateProvider::generate_authorization_ticket()
{
    // create certificate
    Certificate certificate;

    Certificate aa_certificate = this->aa_certificate();
    // section 6 in TS 103 097 v2.1.1
    certificate->issuer.present= Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest;
    HashedId8 aa_certi_hashed = boost::get(calculate_hash(*aa_certificate));
    OCTET_STRING_fromBuf(
        &(certificate->issuer.choice.sha256AndDigest),
        reinterpret_cast<const char *>(aa_certi_hashed.data()),
        aa_certi_hashed.size()
    );

    // section 6 in TS 103 097 v2.1.1
    certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none;
    std::vector<uint8_t> craciId(3, 0);
    OCTET_STRING_fromBuf(
        &certificate->toBeSigned.cracaId,
        reinterpret_cast<const char*>(craciId.data()),
        craciId.size()
    );
    certificate->version = 3;
    certificate->toBeSigned.crlSeries = 0;

    // section 7.2.1 in TS 103 097 v2.1.1
    certificate.add_permission(aid::CA, ByteBuffer({ 1, 0, 0 }));
    certificate.add_permission(aid::DEN, ByteBuffer({ 1, 0xff, 0xff, 0xff}));
    certificate.add_permission(aid::GN_MGMT, ByteBuffer({})); // required for beacons
    certificate.add_permission(aid::IPV6_ROUTING, ByteBuffer({})); // required for routing tests

    // section 6 in TS 103 097 v2.1.1
    // set subject attributes
    // set the verification_key
    Uncompressed coordinates;
    coordinates.x.assign(m_own_key_pair.public_key.x.begin(), m_own_key_pair.public_key.x.end());
    coordinates.y.assign(m_own_key_pair.public_key.y.begin(), m_own_key_pair.public_key.y.end());
    certificate->toBeSigned.verifyKeyIndicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256;
    certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.present = Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256;
    OCTET_STRING_fromBuf(
        &certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.choice.uncompressedP256.x,
        reinterpret_cast<const char*>(coordinates.x.data()),
        coordinates.x.size()
    );
    OCTET_STRING_fromBuf(
        &certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.choice.uncompressedP256.y,
        reinterpret_cast<const char*>(coordinates.y.data()),
        coordinates.y.size()
    );

    // section 6 in TS 103 097 v2.1.1
    // No constraint
    // set validity restriction

    certificate->toBeSigned.validityPeriod.start = v2::convert_time32(m_runtime.now() - std::chrono::hours(1));;
    certificate->toBeSigned.validityPeriod.duration.present = Vanetza_Security_Duration_PR_hours;
    certificate->toBeSigned.validityPeriod.duration.choice.hours = 23;

    sign_authorization_ticket(certificate);

    return certificate;
}

void NaiveCertificateProvider::sign_authorization_ticket(Certificate& certificate)
{
    ByteBuffer data_buffer;
    data_buffer = certificate.convert_for_signing(); // Correct length for P256 signature parts
    certificate.set_signature(m_crypto_backend.sign_data(aa_key_pair().private_key, data_buffer));
}

Certificate NaiveCertificateProvider::generate_aa_certificate(const std::string& subject_name)
{
    Certificate aa_certificate;

    //section 7.2.4 in TS 103 097 v2.1.1
    Certificate root_cert = this->root_certificate();
    aa_certificate->issuer.present= Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest;
    HashedId8 root_certi_hashed = boost::get(calculate_hash(*root_cert));
    OCTET_STRING_fromBuf(
        &(aa_certificate->issuer.choice.sha256AndDigest),
        reinterpret_cast<const char *>(root_certi_hashed.data()),
        root_certi_hashed.size()
    );


    aa_certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_name;
    std::string root_name = "AA-cert";
    ByteBuffer root_name_encoded(root_name.begin(), root_name.end());
        OCTET_STRING_fromBuf(
        &aa_certificate->toBeSigned.id.choice.name,
        reinterpret_cast<const char*>(root_name_encoded.data()),
        root_name_encoded.size()
    );

    // section 6 in TS 103 097 v2.1.1
    std::vector<uint8_t> craciId(3, 0);
    OCTET_STRING_fromBuf(
        &aa_certificate->toBeSigned.cracaId,
        reinterpret_cast<const char*>(craciId.data()),
        craciId.size()
    );
    aa_certificate->version = 3;
    aa_certificate->toBeSigned.crlSeries = 0;

    // section 7.2.4 in TS 103 097 v2.1.1
    // certIssuePermissions shall be used to indicate issuing permissions
    // See https://cpoc.jrc.ec.europa.eu/data/documents/e01941_CPOC_Protocol_v3.0_20240206.pdf for detailled cert_permissions
    // I.3.8. certIssuePermissions with predefined values
    asn1::PsidGroupPermissions* cert_permission_message = asn1::allocate<asn1::PsidGroupPermissions>();
    cert_permission_message->subjectPermissions.present = Vanetza_Security_SubjectPermissions_PR_explicit;
    add_psid_group_permission(cert_permission_message,aid::CA,{0x01, 0xff, 0xfc}, {0xff, 0x00, 0x03});
    add_psid_group_permission(cert_permission_message,aid::DEN,{0x01, 0xff, 0xff, 0xff}, {0xff, 0x00, 0x00, 0x00});
    add_psid_group_permission(cert_permission_message,aid::TLM,{0x01, 0xe0}, {0xff, 0x1f});
    add_psid_group_permission(cert_permission_message,aid::RLT,{0x01, 0xc0}, {0xff,0x3f});
    add_psid_group_permission(cert_permission_message,aid::IVI,{0x01, 0xff, 0xff,0xff,0xff,0xf8}, {0xff,0x00,0x00,0x00,0x00,0x07});
    add_psid_group_permission(cert_permission_message,aid::TLC_R,{0x02, 0xff, 0xff,0xe0}, {0xff, 0x00, 0x00, 0x1f});
    add_psid_group_permission(cert_permission_message,aid::GN_MGMT,{0x00}, {0xff});
    aa_certificate.add_cert_permission(cert_permission_message);

    // section 6 in TS 103 097 v2.1.1
    // set subject attributes
    // set the verification_key
    X_Coordinate_Only coordinates;
    coordinates.x.assign(m_own_key_pair.public_key.x.begin(), m_own_key_pair.public_key.x.end());
    aa_certificate->toBeSigned.verifyKeyIndicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    aa_certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256;
    aa_certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
    OCTET_STRING_fromBuf(
        &aa_certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.choice.x_only,
        reinterpret_cast<const char*>(coordinates.x.data()),
        coordinates.x.size()
    );

    aa_certificate->toBeSigned.validityPeriod.start = v2::convert_time32(m_runtime.now() - std::chrono::hours(1));;
    aa_certificate->toBeSigned.validityPeriod.duration.present = Vanetza_Security_Duration_PR_years;
    aa_certificate->toBeSigned.validityPeriod.duration.choice.hours = 4;

    Uncompressed encryption_key;
    encryption_key.x.assign(m_own_key_pair.public_key.x.begin(), m_own_key_pair.public_key.x.end());
    encryption_key.y.assign(m_own_key_pair.public_key.y.begin(), m_own_key_pair.public_key.y.end());
    aa_certificate->toBeSigned.encryptionKey = asn1::allocate<asn1::PublicEncryptionKey>();
    aa_certificate->toBeSigned.encryptionKey->publicKey.present = Vanetza_Security_BasePublicEncryptionKey_PR_eciesNistP256;
    aa_certificate->toBeSigned.encryptionKey->publicKey.choice.eciesNistP256.present = Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256;
    OCTET_STRING_fromBuf(
        &aa_certificate->toBeSigned.encryptionKey->publicKey.choice.eciesNistP256.choice.uncompressedP256.x,
        reinterpret_cast<const char*>(encryption_key.x.data()),
        encryption_key.x.size()
    );
    OCTET_STRING_fromBuf(
        &aa_certificate->toBeSigned.encryptionKey->publicKey.choice.eciesNistP256.choice.uncompressedP256.y,
        reinterpret_cast<const char*>(encryption_key.y.data()),
        encryption_key.y.size()
    );
    

    sign_authorization_ticket(aa_certificate);

    return aa_certificate;
}

Certificate NaiveCertificateProvider::generate_root_certificate(const std::string& subject_name)
{
    Certificate root_certificate;

    //section 7.2.3 in TS 103 097 v2.1.1
    root_certificate->issuer.present = Vanetza_Security_IssuerIdentifier_PR_self;
    root_certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_name;
    std::string root_name = "Root-CA";
    ByteBuffer root_name_encoded(root_name.begin(), root_name.end());
        OCTET_STRING_fromBuf(
        &root_certificate->toBeSigned.id.choice.name,
        reinterpret_cast<const char*>(root_name_encoded.data()),
        root_name_encoded.size()
    );

    // section 6 in TS 103 097 v2.1.1
    std::vector<uint8_t> craciId(3, 0);
    OCTET_STRING_fromBuf(
        &root_certificate->toBeSigned.cracaId,
        reinterpret_cast<const char*>(craciId.data()),
        craciId.size()
    );
    root_certificate->version = 3;
    root_certificate->toBeSigned.crlSeries = 0;

    // section 7.2.3 in TS 103 097 v2.1.1
    root_certificate.add_permission(aid::CRL, ByteBuffer({0x01}));
    root_certificate.add_permission(aid::CTL, ByteBuffer({0x018}));

    // section 7.2.3 in TS 103 097 v2.1.1
    // certIssuePermissions shall be used to indicate issuing permissions
    // See https://cpoc.jrc.ec.europa.eu/data/documents/e01941_CPOC_Protocol_v3.0_20240206.pdf for detailled cert_permissions
    // I.3.8. certIssuePermissions with predefined values
    auto cert_permission = asn1::allocate<asn1::PsidGroupPermissions>();
    cert_permission->subjectPermissions.present = Vanetza_Security_SubjectPermissions_PR_explicit;
    add_psid_group_permission(cert_permission,aid::SCR,{0x01, 0x3e}, {0xff, 0xc1});
    root_certificate.add_cert_permission(cert_permission);

    auto cert_permission_message = asn1::allocate<asn1::PsidGroupPermissions>();
    cert_permission_message->subjectPermissions.present = Vanetza_Security_SubjectPermissions_PR_explicit;
    add_psid_group_permission(cert_permission_message,aid::CA,{0x01, 0xff, 0xfc}, {0xff, 0x00, 0x03});
    add_psid_group_permission(cert_permission_message,aid::DEN,{0x01, 0xff, 0xff, 0xff}, {0xff, 0x00, 0x00, 0x00});
    add_psid_group_permission(cert_permission_message,aid::TLM,{0x01, 0xe0}, {0xff, 0x1f});
    add_psid_group_permission(cert_permission_message,aid::RLT,{0x01, 0xc0}, {0xff,0x3f});
    add_psid_group_permission(cert_permission_message,aid::IVI,{0x01, 0xff, 0xff,0xff,0xff,0xf8}, {0xff,0x00,0x00,0x00,0x00,0x07});
    add_psid_group_permission(cert_permission_message,aid::TLC_R,{0x02, 0xff, 0xff,0xe0}, {0xff, 0x00, 0x00, 0x1f});
    add_psid_group_permission(cert_permission_message,aid::GN_MGMT,{0x00}, {0xff});
    root_certificate.add_cert_permission(cert_permission_message);

    // section 6 in TS 103 097 v2.1.1
    // set subject attributes
    // set the verification_key
    X_Coordinate_Only coordinates;
    coordinates.x.assign(m_own_key_pair.public_key.x.begin(), m_own_key_pair.public_key.x.end());
    root_certificate->toBeSigned.verifyKeyIndicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    root_certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256;
    root_certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
    OCTET_STRING_fromBuf(
        &root_certificate->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.choice.x_only,
        reinterpret_cast<const char*>(coordinates.x.data()),
        coordinates.x.size()
    );
    root_certificate->toBeSigned.validityPeriod.start = v2::convert_time32(m_runtime.now() - std::chrono::hours(1));;
    root_certificate->toBeSigned.validityPeriod.duration.present = Vanetza_Security_Duration_PR_years;
    root_certificate->toBeSigned.validityPeriod.duration.choice.hours = 4;

    sign_authorization_ticket(root_certificate);

    return root_certificate;
}

} // namespace v3
} // namespace security
} // namespace vanetza

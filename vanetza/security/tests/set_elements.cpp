#include <vanetza/common/byte_sequence.hpp>
#include <vanetza/security/tests/set_elements.hpp>

static const std::size_t ecc_field_size = field_size(PublicKeyAlgorithm::Ecies_Nistp256);

std::list<ItsAidSsp> setSubjectAttribute_Its_Aid_Ssp_List()
{
    std::list<ItsAidSsp> itsAidSsp_list;
    for (int c = 0; c < 10; c++) {
        ItsAidSsp itsAidSsp;
        IntX intx;
        intx.set(c + 30);
        itsAidSsp.its_aid = intx;
        for (int c2 = 0; c2 < 10; c2++) {
            itsAidSsp.service_specific_permissions.push_back(c2 + c);
        }
        itsAidSsp_list.push_back(itsAidSsp);
    }
    return itsAidSsp_list;
}

EncryptionKey setSubjectAttribute_Encryption_Key()
{
    EccPoint point = Uncompressed { random_byte_sequence(ecc_field_size, 1), random_byte_sequence(ecc_field_size, 2) };
    EncryptionKey key;
    ecies_nistp256 ecsie;
    ecsie.public_key = point;
    ecsie.supported_symm_alg = SymmetricAlgorithm::Aes128_Ccm;
    key.key = ecsie;
    return key;
}

std::list<IntX> setSubjectAttribute_Its_Aid_List()
{
    std::list<IntX> intx_list;
    for (int c = 0; c < 5; c++) {
        IntX intx;
        intx.set(c + 1000);
        intx_list.push_back(intx);
    }
    return intx_list;
}

Signature setSignature_Ecdsa_Signature()
{
    Signature sig;
    EcdsaSignature signature;
    signature.R = X_Coordinate_Only { random_byte_sequence(ecc_field_size, 42) };
    ByteBuffer buf;
    for (int c = 0; c < 32; c++) {
        uint8_t byte = c + 1;
        buf.push_back(byte);
    }
    signature.s = buf;
    sig = signature;
    return sig;
}

HashedId8 setSignerInfo_HashedId()
{
    HashedId8 id;
    for (int c = 0; c < 8; c++) {
        id[c] = c + 1;
    }
    return id;
}

CertificateDigestWithOtherAlgorithm setSignerInfo_CertDigest()
{
    CertificateDigestWithOtherAlgorithm cert;
    cert.algorithm = PublicKeyAlgorithm::Ecies_Nistp256;
    for (int c = 0; c < 8; c++) {
        cert.digest[c] = c + 2;
    }
    return cert;
}

std::list<SignerInfo> setCertificate_SignerInfo()
{
    std::list<SignerInfo> list;
    list.push_back(setSignerInfo_HashedId());
    list.push_back(setSignerInfo_CertDigest());
    return list;
}

std::list<SubjectAttribute> setCertificate_SubjectAttributeList()
{
    std::list<SubjectAttribute> list;
    list.push_back(setSubjectAttribute_Encryption_Key());
    list.push_back(setSubjectAttribute_Its_Aid_List());
    return list;
}

std::list<ValidityRestriction> setCertificate_ValidityRestriction()
{
    std::list<ValidityRestriction> list;
    // TODO: set these restrictions in certificate test
    //list.push_back(setValidityRestriction_Region());
    //list.push_back(setValidityRestriction_Time_Start_And_End());
    //list.push_back(setValidityRestriction_Time_Start_And_Duration());
    return list;
}

std::list<Certificate> setSignerInfo_CertificateList()
{
    std::list<Certificate> list;
    Certificate cert;
    cert.version = 0x5;
    cert.signer_info = setCertificate_SignerInfo();
    cert.subject_info = { SubjectType::Enrollment_Credential, random_byte_sequence(28, 1) };
    cert.subject_attributes = setCertificate_SubjectAttributeList();
    cert.validity_restriction = setCertificate_ValidityRestriction();
    cert.signature = setSignature_Ecdsa_Signature();
    list.push_back(cert);
    cert.signer_info = setCertificate_SignerInfo();
    cert.subject_info = { SubjectType::Authorization_Authority, random_byte_sequence(16, 2) };
    cert.subject_attributes = setCertificate_SubjectAttributeList();
    cert.validity_restriction = setCertificate_ValidityRestriction();
    cert.signature = setSignature_Ecdsa_Signature();
    list.push_back(cert);
    return list;
}

Nonce setEncryptionParemeter_nonce()
{
    Nonce nonce;

    for (int c = 0; c < 12; c++) {
        nonce[c] = c + 64;
    }
    return nonce;
}

std::list<HashedId3> setHeaderField_hashedList()
{
    std::list<HashedId3> list;
    for (int c = 0; c < 3; c++) {
        HashedId3 id;
        id[0] = c + 0;
        id[1] = c + 1;
        id[2] = c + 2;
        list.push_back(id);
    }
    return list;
}

ThreeDLocation setHeaderField_threeDLoc()
{
    ThreeDLocation loc;
    loc.latitude = static_cast<geonet::geo_angle_i32t>(1 * boost::units::degree::plane_angle());
    loc.longitude = static_cast<geonet::geo_angle_i32t>(2 * boost::units::degree::plane_angle());
    loc.elevation[0] = 1;
    loc.elevation[1] = 2;
    return loc;
}

std::list<RecipientInfo> setHeaderField_RecipientInfoList()
{
    std::list<RecipientInfo> list;
    RecipientInfo info;
    for (auto& byte : info.cert_id) {
        byte = 1;
    }
    EciesNistP256EncryptedKey key;
    for (size_t c = 0; c < field_size(SymmetricAlgorithm::Aes128_Ccm); ++c) {
        key.c.push_back(c);
    }
    for (size_t c = 0; c < key.t.size(); ++c) {
        key.t[c] = c;
    }
    key.v = Compressed_Lsb_Y_0 { random_byte_sequence(ecc_field_size, 18) };
    info.enc_key = key;
    list.push_back(info);

    RecipientInfo info2;
    EciesNistP256EncryptedKey key2;
    for (auto& byte : info2.cert_id) {
        byte = 2;
    }
    for (size_t c = 0; c < field_size(SymmetricAlgorithm::Aes128_Ccm); ++c) {
        key2.c.push_back(c + 1);
    }
    for (size_t c = 0; c < key2.t.size(); ++c) {
        key2.t[c] = c + 1;
    }
    key2.v = Uncompressed { random_byte_sequence(ecc_field_size, 14), random_byte_sequence(ecc_field_size, 15) };
    info2.enc_key = key2;
    list.push_back(info2);
    return list;
}

std::list<HeaderField> setHeaderField_list()
{
    std::list<HeaderField> list;

    SignerInfo info = setSignerInfo_CertificateList();
    list.push_back(info);

    Time64 time = 983;
    list.push_back(time);

    Time64WithStandardDeviation time64;
    time64.log_std_dev = 1;
    time64.time64 = 2000;
    list.push_back(time64);

    Time32 time32 = 434;
    list.push_back(time32);

    list.push_back(setHeaderField_threeDLoc());
    list.push_back(setHeaderField_hashedList());

    uint16_t uint = 43;
    list.push_back(uint);

    EncryptionParameter param;
    Nonce nonce;
    for (auto& elem : nonce) {
        elem = 22;
    }
    param = nonce;
    list.push_back(param);

    list.push_back(setHeaderField_RecipientInfoList());
    return list;
}


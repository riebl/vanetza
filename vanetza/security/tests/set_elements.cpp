#include <vanetza/security/tests/set_elements.hpp>

EccPoint setEccPoint_uncompressed()
{
    EccPoint point;
    Uncompressed uncompressed;
    for (int c = 0; c < 32; c++) {
        uncompressed.x.push_back(c);
        uncompressed.y.push_back(32 - c);
    }
    point = uncompressed;
    return point;
}

EccPoint setEccPoint_Compressed_Lsb_Y_0()
{
    EccPoint point;
    Compressed_Lsb_Y_0 coord;
    for (int c = 0; c < 32; c++) {
        coord.x.push_back(c);
    }
    point = coord;
    return point;
}

EccPoint setEccPoint_X_Coordinate_Only()
{
    EccPoint point;
    X_Coordinate_Only coord;
    for (int c = 0; c < 32; c++) {
        coord.x.push_back(c);
    }
    point = coord;
    return point;
}

PublicKey setPublicKey_Ecies_Nistp256()
{
    EccPoint point = setEccPoint_uncompressed();
    PublicKey key;
    ecies_nistp256 ecies;
    ecies.public_key = point;
    ecies.supported_symm_alg = SymmetricAlgorithm::Aes128_Ccm;
    key = ecies;
    return key;
}

PublicKey setPublicKey_Ecdsa_Nistp256_With_Sha256()
{
    EccPoint point = setEccPoint_X_Coordinate_Only();
    PublicKey key;
    ecdsa_nistp256_with_sha256 ecdsa;
    ecdsa.public_key = point;
    key = ecdsa;
    return key;
}

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
    EccPoint point = setEccPoint_uncompressed();
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

std::list<ItsAidPriority> setSubjectAttribute_Priority_Its_Aid_List()
{
    std::list<ItsAidPriority> itsAidPriority_list;
    for (int c = 0; c < 22; c++) {
        ItsAidPriority itsAidPriority;
        IntX intx;
        intx.set(c + 35);
        itsAidPriority.its_aid = intx;
        itsAidPriority.max_priority = (125 + c);
        itsAidPriority_list.push_back(itsAidPriority);
    }
    return itsAidPriority_list;
}

std::list<ItsAidPrioritySsp> setSubjectAttribute_Priority_Ssp_List()
{
    std::list<ItsAidPrioritySsp> ssp_list;
    ItsAidPrioritySsp itsAid;
    IntX intx;
    intx.set(10);
    ByteBuffer buf;
    for (int c = 0; c < 5; c++) {
        buf.push_back(c + 100);
    }
    itsAid.its_aid = intx;
    itsAid.max_priority = 15;
    itsAid.service_specific_permissions = buf;
    ssp_list.push_back(itsAid);

    ByteBuffer buf2;
    intx.set(12);
    for (int c = 0; c < 7; c++) {
        buf2.push_back(c + 200);
    }
    itsAid.its_aid = intx;
    itsAid.max_priority = 125;
    itsAid.service_specific_permissions = buf2;

    ssp_list.push_back(itsAid);
    return ssp_list;
}

GeographicRegion setGeographicRegion_CircularRegion()
{
    GeographicRegion reg;
    CircularRegion circle;
    circle.center.latitude = static_cast<geonet::geo_angle_i32t>(12564
        * boost::units::degree::plane_angle());
    circle.center.longtitude = static_cast<geonet::geo_angle_i32t>(654321
        * boost::units::degree::plane_angle());
    reg = circle;
    return reg;
}

GeographicRegion setGeographicRegion_IdentifiedRegion()
{
    GeographicRegion reg;
    IdentifiedRegion id;
    id.region_dictionary = RegionDictionary::Iso_3166_1;
    id.region_identifier = 12345;
    id.local_region.set(546);
    reg = id;
    return reg;
}

GeographicRegion setGeographicRegion_PolygonalRegion()
{
    GeographicRegion reg;
    PolygonalRegion poly;
    for (int c = 0; c < 3; c++) {
        TwoDLocation loc;
        loc.latitude = static_cast<geonet::geo_angle_i32t>((25 + c)
            * boost::units::degree::plane_angle());
        loc.longtitude = static_cast<geonet::geo_angle_i32t>((26 + c)
            * boost::units::degree::plane_angle());
        poly.push_back(loc);
    }
    reg = poly;
    return reg;
}

GeographicRegion setGeographicRegion_RectangularRegion_list()
{
    GeographicRegion reg;
    std::list<RectangularRegion> list;
    for (int c = 0; c < 5; c++) {
        RectangularRegion rectangular;
        rectangular.northwest.latitude = static_cast<geonet::geo_angle_i32t>((1000000 + c)
            * boost::units::degree::plane_angle());
        rectangular.northwest.longtitude = static_cast<geonet::geo_angle_i32t>((1010000 + c)
            * boost::units::degree::plane_angle());
        rectangular.southeast.latitude = static_cast<geonet::geo_angle_i32t>((1020000 + c)
            * boost::units::degree::plane_angle());
        rectangular.southeast.longtitude = static_cast<geonet::geo_angle_i32t>((1030000 + c)
            * boost::units::degree::plane_angle());
        list.push_back(rectangular);
    }
    reg = list;
    return reg;
}

ValidityRestriction setValidityRestriction_Time_End()
{
    EndValidity end = 0x548736;
    ValidityRestriction restriction = end;
    return restriction;
}

ValidityRestriction setValidityRestriction_Time_Start_And_End()
{
    StartAndEndValidity start;
    start.end_validity = 0x54;
    start.start_validity = 0x5712;
    ValidityRestriction restriction = start;
    return restriction;
}

ValidityRestriction setValidityRestriction_Time_Start_And_Duration()
{
    StartAndDurationValidity duration;
    duration.duration = Duration(uint16_t(0x8007));
    duration.start_validity = 0x5712;
    ValidityRestriction restriction = duration;
    return restriction;
}

ValidityRestriction setValidityRestriction_Region()
{
    ValidityRestriction restriction = setGeographicRegion_CircularRegion();
    return restriction;
}

Signature setSignature_Ecdsa_Signature()
{
    Signature sig;
    EcdsaSignature signature;
    signature.R = setEccPoint_X_Coordinate_Only();
    ByteBuffer buf;
    for (int c = 0; c < 32; c++) {
        uint8_t byte = c + 1;
        buf.push_back(byte);
    }
    signature.s = buf;
    sig = signature;
    return sig;
}

SubjectInfo setSubjectInfo()
{
    SubjectInfo sub;
    sub.subject_type = SubjectType::Enrollment_Credential;
    for (int c = 0; c < 24; c++) {
        sub.subject_name.push_back(25 + c);
    }
    return sub;
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
    list.push_back(setValidityRestriction_Region());
    list.push_back(setValidityRestriction_Time_Start_And_End());
    list.push_back(setValidityRestriction_Time_Start_And_Duration());
    return list;
}

std::list<Certificate> setSignerInfo_CertificateList()
{
    std::list<Certificate> list;
    Certificate cert;
    cert.version = 0x5;
    cert.signer_info = setCertificate_SignerInfo();
    cert.subject_info = setSubjectInfo();
    cert.subject_attributes = setCertificate_SubjectAttributeList();
    cert.validity_restriction = setCertificate_ValidityRestriction();
    cert.signature = setSignature_Ecdsa_Signature();
    list.push_back(cert);
    cert.signer_info = setCertificate_SignerInfo();
    cert.subject_info = setSubjectInfo();
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

RecipientInfo setRecipientInfo()
{
    RecipientInfo info;
    EciesNistP256EncryptedKey &ecies = boost::get<EciesNistP256EncryptedKey>(info.enc_key);
    for (size_t c = 0; c < info.cert_id.size(); ++c) {
        info.cert_id[c] = 10 + c;
    }
    for (size_t c = 0; c < field_size(SymmetricAlgorithm::Aes128_Ccm); ++c) {
        ecies.c.push_back(c);
    }
    for (size_t c = 0; c < ecies.t.size(); ++c) {
        ecies.t[c] = c;
    }
    ecies.v = setEccPoint_Compressed_Lsb_Y_0();
    return info;
}

std::list<RecipientInfo> setRecipientInfoList()
{
    std::list<RecipientInfo> list;
    list.push_back(setRecipientInfo());
    list.push_back(setRecipientInfo());
    return list;
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
    loc.longtitude = static_cast<geonet::geo_angle_i32t>(2 * boost::units::degree::plane_angle());
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
    key.v = setEccPoint_Compressed_Lsb_Y_0();
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
    key2.v = setEccPoint_uncompressed();
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

std::list<Payload> setPayload_List()
{
    std::list<Payload> list;
    Payload u;
    u.type = PayloadType::Unsecured;
    for (int c = 0; c < 12; c++) {
        u.buffer.push_back(c);
    }
    list.push_back(u);
    Payload s;
    s.type = PayloadType::Signed;
    for (int c = 0; c < 12; c++) {
        s.buffer.push_back(10 + c);
    }
    list.push_back(s);
    Payload e;
    e.type = PayloadType::Signed_And_Encrypted;
    for (int c = 0; c < 12; c++) {
        e.buffer.push_back(100 + c);
    }
    list.push_back(e);

    return list;
}

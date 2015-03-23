#include <vanetza/security/tests/test_elements.hpp>

void testEccPoint_uncompressed(const EccPoint& point, const EccPoint& outPoint) {
    EXPECT_EQ(get_type(point), get_type(outPoint));
    EXPECT_EQ(boost::get<Uncompressed>(point).x,
            boost::get<Uncompressed>(outPoint).x);
    EXPECT_EQ(boost::get<Uncompressed>(point).y,
            boost::get<Uncompressed>(outPoint).y);
}

void testEccPoint_Compressed_Lsb_Y_0(const EccPoint& point, const EccPoint& outPoint) {
    EXPECT_EQ(get_type(point), get_type(outPoint));
    EXPECT_EQ(boost::get<Compressed_Lsb_Y_0>(point).x,
            boost::get<Compressed_Lsb_Y_0>(outPoint).x);
}

void testEccPoint_X_Coordinate_Only(const EccPoint& point, const EccPoint& outPoint) {
    EXPECT_EQ(get_type(point), get_type(outPoint));
    EXPECT_EQ(boost::get<X_Coordinate_Only>(point).x,
            boost::get<X_Coordinate_Only>(outPoint).x);
}

void testPublicKey_Ecies_Nistp256(const PublicKey& key, const PublicKey& deKey) {
    int size = get_size(deKey);
    EXPECT_EQ(get_type(key), get_type(deKey));
    ecies_nistp256 ecies = boost::get<ecies_nistp256>(key);
    ecies_nistp256 deEcies = boost::get<ecies_nistp256>(deKey);
    testEccPoint_uncompressed(ecies.public_key, deEcies.public_key);
    EXPECT_EQ(boost::get<ecies_nistp256>(deKey).supported_symm_alg,
            boost::get<ecies_nistp256>(key).supported_symm_alg);
    EXPECT_EQ(67, size);
}

void testPublicKey_Ecdsa_Nistp256_With_Sha256(const PublicKey& key, const PublicKey& deKey ) {
    int size = get_size(deKey);
    EXPECT_EQ(get_type(key), get_type(deKey));
    ecdsa_nistp256_with_sha256 ecdsa = boost::get<ecdsa_nistp256_with_sha256>(key);
    ecdsa_nistp256_with_sha256 deEcdsa = boost::get<ecdsa_nistp256_with_sha256>(deKey);
    testEccPoint_X_Coordinate_Only(ecdsa.public_key, deEcdsa.public_key);
    EXPECT_EQ(34, size);
}

void testSubjectAttribute_Encryption_Key(const SubjectAttribute& sub, const SubjectAttribute& deSub) {
    EncryptionKey key = boost::get<EncryptionKey>(sub);
    EncryptionKey deKey = boost::get<EncryptionKey>(deSub);
    EXPECT_EQ(get_type(deSub), get_type(sub));
    testPublicKey_Ecies_Nistp256(key.key, deKey.key);
}

void testSubjectAttribute_Its_Aid_List(const SubjectAttribute& sub, const SubjectAttribute& deSub) {
    EXPECT_EQ(get_type(deSub), get_type(sub));
    auto iter = boost::get<std::list<IntX>>(deSub).begin();
    for (int c = 0; c < 5; c++) {
        EXPECT_EQ(iter->get(), c + 1000);
        iter++;
    }
}

void testSubjectAttribute_Its_Aid_Ssp_List(const SubjectAttribute& sub, const SubjectAttribute& deSub) {
    EXPECT_EQ(get_type(deSub), get_type(sub));
    int c = 0;
    int c2 = 0;
    for(auto& itsAid : boost::get<std::list<ItsAidSsp>>(deSub)){
        EXPECT_EQ(itsAid.its_aid.get(), c + 30);
        c2 = 0;
        for (auto& service_specific_permission : itsAid.service_specific_permissions) {
            uint8_t x;
            x = uint8_t(service_specific_permission);
            EXPECT_EQ(int(x), c2 + c);
            c2++;
        }
        c++;
    }
}

void testSubjectAttribute_Priority_Its_Aid_List(const SubjectAttribute& sub, const SubjectAttribute& deSub) {
    EXPECT_EQ(get_type(deSub), get_type(sub));
    int c = 0;
    for (auto& itsAidPriorityList : boost::get<std::list<ItsAidPriority>>(deSub)) {
        EXPECT_EQ(itsAidPriorityList.its_aid.get(), c + 35);
        EXPECT_EQ(itsAidPriorityList.max_priority, (125+c));
        c++;
    }
}

void testSubjectAttribute_Priority_Ssp_List(const SubjectAttribute& sub, const SubjectAttribute& deSub) {
    EXPECT_EQ(get_type(deSub), get_type(sub));
    auto iter = boost::get<std::list<ItsAidPrioritySsp>>(deSub).begin();
    EXPECT_EQ(iter->its_aid.get(), 10);
    EXPECT_EQ(iter->max_priority, 15);
    auto buf_it = iter->service_specific_permissions.begin();
    for (int c = 0; c < 5; c++) {
        uint8_t x;
        x = uint8_t(*buf_it);
        EXPECT_EQ(x, c + 100);
        buf_it++;
    }
    iter++;
    EXPECT_EQ(iter->its_aid.get(), 12);
    EXPECT_EQ(iter->max_priority, 125);
    buf_it = iter->service_specific_permissions.begin();
    for (int c = 0; c < 7; c++) {
        uint8_t x;
        x = uint8_t(*buf_it);
        EXPECT_EQ(int(x), c + 200);
        buf_it++;
    }
}

void testGeograpicRegion_CircularRegion(const GeograpicRegion& reg, const GeograpicRegion& deReg) {
    EXPECT_EQ(get_type(reg), get_type(deReg));
    EXPECT_EQ(boost::get<CircularRegion>(reg).center.latitude,
             boost::get<CircularRegion>(deReg).center.latitude);
    EXPECT_EQ(boost::get<CircularRegion>(reg).center.longtitude,
             boost::get<CircularRegion>(deReg).center.longtitude);
}

void testGeograpicRegion_IdentifiedRegion(const GeograpicRegion& reg, const GeograpicRegion& deReg) {
    EXPECT_EQ(get_type(reg), get_type(deReg));
    EXPECT_EQ(boost::get<IdentifiedRegion>(reg).region_dictionary,
            boost::get<IdentifiedRegion>(deReg).region_dictionary);
    EXPECT_EQ(boost::get<IdentifiedRegion>(reg).local_region.get(),
            boost::get<IdentifiedRegion>(deReg).local_region.get());
    EXPECT_EQ(boost::get<IdentifiedRegion>(reg).region_identifier,
            boost::get<IdentifiedRegion>(deReg).region_identifier);
}

void testGeograpicRegion_PolygonalRegion(const GeograpicRegion& reg, const GeograpicRegion& deReg) {
    EXPECT_EQ(get_type(reg), get_type(deReg));
    int c = 0;
    for (auto& region : boost::get<PolygonalRegion>(deReg)) {
        EXPECT_EQ(region.latitude, static_cast<geonet::geo_angle_i32t>((25 + c) * boost::units::degree::plane_angle()));
        EXPECT_EQ(region.longtitude, static_cast<geonet::geo_angle_i32t>((26 + c) * boost::units::degree::plane_angle()));
        c++;
    }
}

void testGeograpicRegion_RectangularRegion_list(const GeograpicRegion& reg, const GeograpicRegion& deReg) {
    RegionType detype = get_type(deReg);
    int c = 0;
    EXPECT_EQ(get_type(reg), get_type(deReg));
    for (auto& rectangular : boost::get<std::list<RectangularRegion>>(deReg)) {
        EXPECT_EQ(rectangular.nortwest.latitude, static_cast<geonet::geo_angle_i32t>((1000000 + c) * boost::units::degree::plane_angle()));
        EXPECT_EQ(rectangular.nortwest.longtitude, static_cast<geonet::geo_angle_i32t>((1010000 + c) * boost::units::degree::plane_angle()));
        EXPECT_EQ(rectangular.southeast.latitude, static_cast<geonet::geo_angle_i32t>((1020000 + c) * boost::units::degree::plane_angle()));
        EXPECT_EQ(rectangular.southeast.longtitude, static_cast<geonet::geo_angle_i32t>((1030000 + c) * boost::units::degree::plane_angle()));
        c++;
    }
}

void testValidityRestriction_Time_End(const ValidityRestriction& res, const ValidityRestriction& deserializedRes) {
    EXPECT_EQ(get_type(res), get_type(deserializedRes));
    EXPECT_EQ(boost::get<EndValidity>(res), boost::get<EndValidity>(deserializedRes));
}

void testValidityRestriction_Time_Start_And_End(const ValidityRestriction& res, const ValidityRestriction& deserializedRes) {
    EXPECT_EQ(get_type(res), get_type(deserializedRes));
    EXPECT_EQ(boost::get<StartAndEndValidity>(res).end_validity, boost::get<StartAndEndValidity>(deserializedRes).end_validity);
    EXPECT_EQ(boost::get<StartAndEndValidity>(res).start_validity, boost::get<StartAndEndValidity>(deserializedRes).start_validity);
}

void testValidityRestriction_Time_Start_And_Duration(const ValidityRestriction& res, const ValidityRestriction& deserializedRes) {
    EXPECT_EQ(get_type(res), get_type(deserializedRes));
    EXPECT_EQ(boost::get<StartAndDurationValidity>(res).start_validity, boost::get<StartAndDurationValidity>(deserializedRes).start_validity);
    Duration a = boost::get<StartAndDurationValidity>(res).duration;
    Duration b = boost::get<StartAndDurationValidity>(deserializedRes).duration;
    EXPECT_EQ(a.raw(), b.raw());
}

void testValidityRestriction_Region(const ValidityRestriction& res, const ValidityRestriction& deserializedRes) {
    EXPECT_EQ(get_type(res), get_type(deserializedRes));
    testGeograpicRegion_CircularRegion(boost::get<GeograpicRegion>(res), boost::get<GeograpicRegion>(deserializedRes));
}

void testSignature_Ecdsa_Signature(const Signature& sig, const Signature& deserializedSig) {
    EXPECT_EQ(get_type(sig), get_type(deserializedSig));
    testEccPoint_X_Coordinate_Only(boost::get<EcdsaSignature>(sig).R, boost::get<EcdsaSignature>(deserializedSig).R);
    EXPECT_EQ(boost::get<EcdsaSignature>(sig).s, boost::get<EcdsaSignature>(deserializedSig).s);
}

void testSubjectInfo(const SubjectInfo& sub, const SubjectInfo& desub) {
    EXPECT_EQ(sub.subject_name.size(), get_size(sub)-1);
    EXPECT_EQ(sub.subject_name.size(), desub.subject_name.size());
    EXPECT_EQ(sub.subject_type, desub.subject_type);
    EXPECT_EQ(sub.subject_name, desub.subject_name);
}

void testCertificate_SignerInfo(const std::list<SignerInfo>& list, const std::list<SignerInfo>& deList) {
    auto it = list.begin();
    auto deIt = deList.begin();
    EXPECT_EQ(boost::get<HashedId8>(*it++), boost::get<HashedId8>(*deIt++));
    EXPECT_EQ(boost::get<CertificateDigestWithOtherAlgorithm>(*it).algorithm, boost::get<CertificateDigestWithOtherAlgorithm>(*deIt).algorithm);
    EXPECT_EQ(boost::get<CertificateDigestWithOtherAlgorithm>(*it).digest, boost::get<CertificateDigestWithOtherAlgorithm>(*deIt).digest);
}

void testCertificate_SubjectAttributeList(const std::list<SubjectAttribute>& list, const std::list<SubjectAttribute>& deList) {
    auto it = list.begin();
    auto deIt = deList.begin();
    testSubjectAttribute_Encryption_Key(*it++, *deIt++);
    testSubjectAttribute_Its_Aid_List(*it, *deIt);
}

void testCertificate_ValidityRestrictionList(const std::list<ValidityRestriction>& list, const std::list<ValidityRestriction>& deList) {
    auto it = list.begin();
    auto deIt = deList.begin();
    testValidityRestriction_Region(*it++, *deIt++);
    testValidityRestriction_Time_Start_And_End(*it++, *deIt++);
    testValidityRestriction_Time_Start_And_Duration(*it++, *deIt++);
}

void testSignerInfo_Certificate(const Certificate& cert, const Certificate& deCert ) {
    EXPECT_EQ(cert.version, deCert.version);
    testCertificate_SignerInfo(cert.signer_info, deCert.signer_info);
    testSubjectInfo(cert.subject_info, deCert.subject_info);
    testCertificate_SubjectAttributeList(cert.subject_attributes, deCert.subject_attributes);
    testCertificate_ValidityRestrictionList(cert.validity_restriction, deCert.validity_restriction);
    testSignature_Ecdsa_Signature(cert.signature, deCert.signature);
}

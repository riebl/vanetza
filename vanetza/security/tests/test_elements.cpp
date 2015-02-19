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

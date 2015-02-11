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

void testPublicKey_Ecdsa_Nistp256_With_Sha256(const PublicKey& key, const PublicKey& deKey) {
    int size = get_size(deKey);
    EXPECT_EQ(get_type(key), get_type(deKey));
    ecdsa_nistp256_with_sha256 ecdsa = boost::get<ecdsa_nistp256_with_sha256>(key);
    ecdsa_nistp256_with_sha256 deEcdsa = boost::get<ecdsa_nistp256_with_sha256>(deKey);
    testEccPoint_X_Coordinate_Only(ecdsa.public_key, deEcdsa.public_key);
    EXPECT_EQ(34, size);
}

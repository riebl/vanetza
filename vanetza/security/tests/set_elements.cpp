#include <vanetza/security/tests/set_elements.hpp>

EccPoint setEccPoint_uncompressed() {
    EccPoint point;
    Uncompressed uncompressed;
    for (int c = 0; c < 32; c++) {
        uncompressed.x.push_back(c);
        uncompressed.y.push_back(32 - c);
    }
    point = uncompressed;
    return point;
}

EccPoint setEccPoint_Compressed_Lsb_Y_0() {
    EccPoint point;
    EccPointType type = EccPointType::Compressed_Lsb_Y_0;
    Compressed_Lsb_Y_0 coord;
    for (int c = 0; c < 32; c++) {
        coord.x.push_back(c);
    }
    point = coord;
    return point;
}

EccPoint setEccPoint_X_Coordinate_Only() {
    EccPoint point;
    EccPointType type = EccPointType::X_Coordinate_Only;
    X_Coordinate_Only coord;
    for (int c = 0; c < 32; c++) {
        coord.x.push_back(c);
    }
    point = coord;
    return point;
}

PublicKey setPublicKey_Ecies_Nistp256() {
    EccPoint point = setEccPoint_uncompressed();
    PublicKey key;
    ecies_nistp256 ecies;
    ecies.public_key = point;
    ecies.supported_symm_alg = SymmetricAlgorithm::Aes128_Ccm;
    key = ecies;
    return key;
}

PublicKey setPublicKey_Ecdsa_Nistp256_With_Sha256() {
    EccPoint point = setEccPoint_X_Coordinate_Only();
    PublicKey key;
    ecdsa_nistp256_with_sha256 ecdsa;
    ecdsa.public_key = point;
    key = ecdsa;
    return key;
}

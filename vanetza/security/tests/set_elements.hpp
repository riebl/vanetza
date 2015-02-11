#ifndef SETELEMENTS_HPP_CISPFKMVCOSDJ
#define SETELEMENTS_HPP_CISPFKMVCOSDJ

#include <gtest/gtest.h>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/public_key.hpp>

using namespace vanetza::security;
using namespace vanetza;
using namespace std;

EccPoint setEccPoint_uncompressed();
EccPoint setEccPoint_Compressed_Lsb_Y_0();
EccPoint setEccPoint_X_Coordinate_Only();
PublicKey setPublicKey_Ecies_Nistp256();
PublicKey setPublicKey_Ecdsa_Nistp256_With_Sha256();

#endif /* SETELEMENTS_HPP_ */

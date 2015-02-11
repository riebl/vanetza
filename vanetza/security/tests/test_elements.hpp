#ifndef TEST_ELEMENTS_HPP_KISBVCLSDSICN
#define TEST_ELEMENTS_HPP_KISBVCLSDSICN

#include <gtest/gtest.h>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/public_key.hpp>

using namespace vanetza::security;
using namespace vanetza;
using namespace std;

void testEccPoint_uncompressed(const EccPoint&, const EccPoint&);
void testEccPoint_Compressed_Lsb_Y_0(const EccPoint&, const EccPoint&);
void testEccPoint_X_Coordinate_Only(const EccPoint&, const EccPoint&);
void testPublicKey_Ecies_Nistp256(const PublicKey&, const PublicKey&);
void testPublicKey_Ecdsa_Nistp256_With_Sha256(const PublicKey&, const PublicKey&);

#endif /* TEST_ELEMENTS_HPP_KISBVCLSDSICN */

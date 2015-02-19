#ifndef SETELEMENTS_HPP_CISPFKMVCOSDJ
#define SETELEMENTS_HPP_CISPFKMVCOSDJ

#include <gtest/gtest.h>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/subject_attribute.hpp>

using namespace vanetza::security;
using namespace vanetza;
using namespace std;

EccPoint setEccPoint_uncompressed();
EccPoint setEccPoint_Compressed_Lsb_Y_0();
EccPoint setEccPoint_X_Coordinate_Only();
PublicKey setPublicKey_Ecies_Nistp256();
PublicKey setPublicKey_Ecdsa_Nistp256_With_Sha256();

EncryptionKey setSubjectAttribute_Encryption_Key();
std::list<ItsAidSsp> setSubjectAttribute_Its_Aid_Ssp_List();
std::list<IntX> setSubjectAttribute_Its_Aid_List();
std::list<ItsAidPriority> setSubjectAttribute_Priority_Its_Aid_List();
std::list<ItsAidPrioritySsp> setSubjectAttribute_Priority_Ssp_List();

#endif /* SETELEMENTS_HPP_ */

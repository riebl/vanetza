#ifndef TEST_ELEMENTS_HPP_KISBVCLSDSICN
#define TEST_ELEMENTS_HPP_KISBVCLSDSICN

#include <gtest/gtest.h>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/region.hpp>
#include <vanetza/security/subject_attribute.hpp>
#include <vanetza/security/validity_restriction.hpp>

using namespace vanetza::security;
using namespace vanetza;
using namespace std;

void testEccPoint_uncompressed(const EccPoint&, const EccPoint&);
void testEccPoint_Compressed_Lsb_Y_0(const EccPoint&, const EccPoint&);
void testEccPoint_X_Coordinate_Only(const EccPoint&, const EccPoint&);
void testPublicKey_Ecies_Nistp256(const PublicKey&, const PublicKey&);
void testPublicKey_Ecdsa_Nistp256_With_Sha256(const PublicKey&, const PublicKey&);

void testSubjectAttribute_Encryption_Key(const SubjectAttribute&, const SubjectAttribute&);
void testSubjectAttribute_Its_Aid_List(const SubjectAttribute&, const SubjectAttribute&);
void testSubjectAttribute_Its_Aid_Ssp_List(const SubjectAttribute&, const SubjectAttribute&);
void testSubjectAttribute_Priority_Its_Aid_List(const SubjectAttribute&, const SubjectAttribute&);
void testSubjectAttribute_Priority_Ssp_List(const SubjectAttribute&, const SubjectAttribute&);

void testGeograpicRegion_CircularRegion(const GeograpicRegion&, const GeograpicRegion&);
void testGeograpicRegion_IdentifiedRegion(const GeograpicRegion&, const GeograpicRegion&);
void testGeograpicRegion_PolygonalRegion(const GeograpicRegion&, const GeograpicRegion&);
void testGeograpicRegion_RectangularRegion_list(const GeograpicRegion&, const GeograpicRegion&);

void testValidityRestriction_Time_End(const ValidityRestriction&, const ValidityRestriction&);
void testValidityRestriction_Time_Start_And_End(const ValidityRestriction&, const ValidityRestriction&);
void testValidityRestriction_Time_Start_And_Duration(const ValidityRestriction&, const ValidityRestriction&);
void testValidityRestriction_Region(const ValidityRestriction&, const ValidityRestriction&);

#endif /* TEST_ELEMENTS_HPP_KISBVCLSDSICN */

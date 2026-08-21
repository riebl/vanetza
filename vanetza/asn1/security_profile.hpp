#ifndef VANETZA_ASN1_SECURITY_PROFILE_HPP
#define VANETZA_ASN1_SECURITY_PROFILE_HPP

#ifdef VANETZA_WITH_PQC
#define VANETZA_ASN1_SECURITY_HEADER(header) <vanetza/asn1/systemx-pqc/header>
#else
#define VANETZA_ASN1_SECURITY_HEADER(header) <vanetza/asn1/security/header>
#endif

#endif // VANETZA_ASN1_SECURITY_PROFILE_HPP

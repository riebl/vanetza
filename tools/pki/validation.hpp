#pragma once

#include "sha.hpp"
#include <vanetza/asn1/security/EtsiTs103097Data.h>
#include <vanetza/common/byte_buffer.hpp>

namespace vanetza
{
namespace pki
{

class Certificate;
class CertificateStorage;
class HashedId8;
class SecurityModule;

bool validate(SecurityModule&, const Vanetza_Security_EtsiTs103097Data_t&, const Certificate&);
bool validate(SecurityModule&, const Vanetza_Security_SignedData_t&, const Vanetza_Security_Certificate_t&);

// True iff the response's requestHash echoes the request: the leftmost 16 octets of the request's SHA-256
bool check_request_hash(const Sha256Hash& request_digest, const ByteBuffer& response_hash);

const Vanetza_Security_SignedData_t* get_signed_data(const Vanetza_Security_EtsiTs103097Data_t&);
const Vanetza_Security_Opaque_t* get_unsecured_data(const Vanetza_Security_EtsiTs103097Data_t&);
bool signed_by(SecurityModule&, const Vanetza_Security_SignedData_t&, const HashedId8&);
HashAlgorithm get_hash_algorithm(const Vanetza_Security_SignedData_t&);

template<typename Hash>
Hash calculate_digest(SecurityModule&, const Vanetza_Security_ToBeSignedData_t&, const Vanetza_Security_Certificate_t*);

template<>
Sha256Hash calculate_digest(SecurityModule&, const Vanetza_Security_ToBeSignedData_t&,
    const Vanetza_Security_Certificate_t*);

template<>
Sha384Hash calculate_digest(SecurityModule&, const Vanetza_Security_ToBeSignedData_t&,
    const Vanetza_Security_Certificate_t*);

} // namespace pki
} // namespace vanetza

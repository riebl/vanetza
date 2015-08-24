#ifndef WEB_VALIDATOR_HPP_UENVJNSAEISNF
#define WEB_VALIDATOR_HPP_UENVJNSAEISNF

#include <vanetza/security/secured_message.hpp>

using namespace vanetza;
using namespace security;

// WebValidator refers to https://werkzeug.dcaiti.tu-berlin.de/etsi/ts103097/

void stream_from_string(std::stringstream&, const char*);

void byteBuffer_from_string(ByteBuffer&, const char*);

std::list<SubjectAttribute> SetWebValidator_SecuredMessage3_Attribute();
std::list<ValidityRestriction> setWebValidator_SecuredMessage3_Restriction();
Signature setWebValidator_SecuredMessage3_Signature();

#endif /* WEB_VALIDATOR_HPP_UENVJNSAEISNF */

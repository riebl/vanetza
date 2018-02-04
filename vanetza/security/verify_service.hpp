#ifndef VERIFY_SERVICE_HPP_BR4ISDBH
#define VERIFY_SERVICE_HPP_BR4ISDBH

#include <boost/optional.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/decap_confirm.hpp>
#include <vanetza/security/decap_request.hpp>
#include <functional>

namespace vanetza
{

// forward declaration
class Runtime;

namespace security
{

// forward declarations
class Backend;
class CertificateCache;
class CertificateProvider;
class CertificateValidator;
class SignHeaderPolicy;

/**
 * Equivalent of SN-VERIFY service in TS 102 723-8 V1.1.1
 */
using VerifyService = std::function<DecapConfirm(DecapRequest&)>;

/**
 * Get verify service with basic certificate and signature checks
 * \param rt runtime
 * \param certificate_provider certificate provider
 * \param certificate_validator certificate validator
 * \param backend crypto backend
 * \param certificate_cache certificate cache
 * \param sign_header_policy sign header policy to report unknown certificates
 * \return callable verify service
 */
VerifyService straight_verify_service(Runtime&, CertificateProvider&, CertificateValidator&, Backend&, CertificateCache&, SignHeaderPolicy&);

/**
 * Get insecure dummy verify service without any checks
 * \param confirm confirm report result
 * \return callable verify service
 */
VerifyService dummy_verify_service(DecapConfirm confirm);

} // namespace security
} // namespace vanetza

#endif /* VERIFY_SERVICE_HPP_BR4ISDBH */

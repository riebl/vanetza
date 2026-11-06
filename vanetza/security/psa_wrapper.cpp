#include <vanetza/security/psa_wrapper.hpp>
#include <mutex>

namespace vanetza
{
namespace security
{
namespace psa
{

psa_status_t initialize()
{
    static std::once_flag flag;
    static psa_status_t status = PSA_ERROR_BAD_STATE;
    std::call_once(flag, [] { status = psa_crypto_init(); });
    return status;
}

Key::~Key()
{
    psa_destroy_key(m_id);
}

} // namespace psa
} // namespace security
} // namespace vanetza

#ifndef VANETZA_TRUST_STORE_HPP
#define VANETZA_TRUST_STORE_HPP

#include <map>
#include <vector>
#include "certificate.hpp"

namespace vanetza
{
namespace security
{

class TrustStore
{
public:
    TrustStore(std::vector<Certificate> trusted_certificates);

    std::vector<Certificate> find_by_id(HashedId8 id);

private:
    std::multimap<HashedId8, Certificate> certificates;
};

} // namespace security
} // namespace vanetza

#endif /* VANETZA_TRUST_STORE_HPP */

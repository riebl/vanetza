#pragma once

#include <boost/optional/optional.hpp>

namespace vanetza
{
namespace pki
{

class CertificateTrustList;
class HashedId8;

class TrustListStorage
{
public:
    virtual ~TrustListStorage() = default;
    virtual void store(const CertificateTrustList&) = 0;
    virtual boost::optional<CertificateTrustList> fetch(const HashedId8&) const = 0;
};

} // namespace pki
} // namespace vanetza

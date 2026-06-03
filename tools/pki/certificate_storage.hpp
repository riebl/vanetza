#pragma once

#include "certificate.hpp"
#include "hashed_id8.hpp"
#include <boost/optional/optional.hpp>
#include <boost/range/any_range.hpp>

namespace vanetza
{
namespace pki
{

/// \brief Lazy, single-pass view over stored HashedId8s.
using HashedId8Range = boost::any_range<HashedId8, boost::single_pass_traversal_tag, HashedId8, std::ptrdiff_t>;

class CertificateStorage
{
public:
    virtual ~CertificateStorage() = default;
    virtual boost::optional<Certificate> fetch(const HashedId8&) const = 0;
    virtual void store(const Certificate&) = 0;
    virtual bool erase(const HashedId8&) = 0;
    virtual HashedId8Range list() const = 0;
};

} // namespace pki
} // namespace vanetza

#ifndef PDU_HPP_PQEC9PDO
#define PDU_HPP_PQEC9PDO

#include <vanetza/geonet/header_variant.hpp>
#include <vanetza/geonet/serialization.hpp>
#include <boost/optional.hpp>
#include <cstddef>

namespace vanetza
{
// forward declarations
namespace security { class SecuredMessageV2; }

namespace geonet
{

struct BasicHeader;
struct CommonHeader;

class Pdu
{
public:
    using SecuredMessage = security::SecuredMessageV2;

    virtual BasicHeader& basic() = 0;
    virtual const BasicHeader& basic() const = 0;
    virtual CommonHeader& common() = 0;
    virtual const CommonHeader& common() const = 0;
    virtual SecuredMessage* secured() = 0;
    virtual const SecuredMessage* secured() const = 0;
    virtual void serialize(OutputArchive&) const = 0;
    virtual HeaderConstRefVariant extended_variant() const = 0;
    virtual Pdu* clone() const = 0;
    virtual std::size_t length() const = 0;
    virtual ~Pdu() {}
};

inline void serialize(const Pdu& pdu, OutputArchive& ar)
{
    pdu.serialize(ar);
}

} // namespace geonet
} // namespace vanetza

#endif /* PDU_HPP_PQEC9PDO */


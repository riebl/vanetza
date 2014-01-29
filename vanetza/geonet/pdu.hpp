#ifndef PDU_HPP_PQEC9PDO
#define PDU_HPP_PQEC9PDO

#include <vanetza/geonet/serialization.hpp>
#include <cstddef>

namespace vanetza
{
namespace geonet
{

struct BasicHeader;
struct CommonHeader;

class Pdu
{
public:
    virtual BasicHeader& basic() = 0;
    virtual const BasicHeader& basic() const = 0;
    virtual CommonHeader& common() = 0;
    virtual const CommonHeader& common() const = 0;
    virtual void serialize(OutputArchive&) const = 0;
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


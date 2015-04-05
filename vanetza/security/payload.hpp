#ifndef PAYLOAD_HPP_R8IXQBSL
#define PAYLOAD_HPP_R8IXQBSL

#include <cstdint>
#include <boost/strong_typedef.hpp>
#include <boost/variant.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/serialization.hpp>

namespace vanetza
{
namespace security
{

enum class PayloadType : uint8_t
{
    Unsecured = 0,
    Signed = 1,
    Encrypted = 2,
    Signed_External = 3,
    Signed_And_Encrypted = 4
};

struct Unsecured: ByteBuffer {};
struct Signed: ByteBuffer {};
struct Encrypted: ByteBuffer {};
struct SignedExternal: ByteBuffer {};
struct SignedAndEncrypted: ByteBuffer {};

typedef boost::variant<Unsecured, Signed, Encrypted, SignedExternal, SignedAndEncrypted> Payload;


PayloadType get_type(const Payload&);

size_t get_size(const Payload&);
size_t get_size(const std::list<Payload>&);

void serialize(OutputArchive& ar, const ByteBuffer&);
void serialize(OutputArchive& ar, const Payload&);
void serialize(OutputArchive& ar, const std::list<Payload>);

size_t deserialize(InputArchive& ar, ByteBuffer&);
size_t deserialize(InputArchive& ar, Payload&);
size_t deserialize(InputArchive& ar, std::list<Payload>&);

} // namespace security
} // namespace vanetza

#endif /* PAYLOAD_HPP_R8IXQBSL */


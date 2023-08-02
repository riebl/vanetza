
#ifndef SECURED_MESSAGE_HPP_DCBC74AC
#define SECURED_MESSAGE_HPP_DCBC74AC

#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs103097Data.h>
#include <vanetza/common/archives.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/net/packet_variant.hpp>
#include <vanetza/security/hashed_id.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <cstdint>
#include <boost/optional/optional_fwd.hpp>
#include <boost/variant/variant_fwd.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

struct SecuredMessage : public asn1::asn1c_oer_wrapper<EtsiTs103097Data_t>
{
    using Time64 = std::uint64_t;
    using SignerIdentifier = boost::variant<const HashedId8_t*, const Certificate_t*>;

    SecuredMessage();

    uint8_t protocol_version() const;
    ItsAid its_aid() const;
    PacketVariant payload() const;
    bool is_signed() const;
    boost::optional<Time64> generation_time() const;
    boost::optional<Signature> signature() const;
    SignerIdentifier signer_identifier() const;
    ByteBuffer signing_payload() const;
};

/**
 * \brief Calculate size of encoded secured message
 * \param msg secured message
 * \return number of octets needed to serialize this message
 */
size_t get_size(const SecuredMessage& msg);

/**
 * \brief Serialize a secured message
 *
 * @param ar output archive
 * @param msg message to be serialized
 */
void serialize(OutputArchive& ar, const SecuredMessage& msg);

/**
 * \brief Deserialize a secured message
 *
 * \param ar input archive
 * \param msg destination message object
 * \return size of deserialized message
 */
size_t deserialize(InputArchive& ar, SecuredMessage& msg);

ByteBuffer get_payload(const Opaque_t*);
ByteBuffer get_payload(const SignedData*);

boost::optional<HashedId8> get_certificate_id(const SecuredMessage::SignerIdentifier&);

} // namespace v3
} // namespace security
} // namespace vanetza

#endif /* SECURED_MESSAGE_HPP_DCBC74AC */

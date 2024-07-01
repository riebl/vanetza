
#ifndef SECURED_MESSAGE_HPP_DCBC74AC
#define SECURED_MESSAGE_HPP_DCBC74AC

#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs103097Data.h>
#include <vanetza/security/v3/signer_info.hpp>
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

    void set_its_aid(ItsAid its_aid);
    void set_generation_time(Time64 time);
    void set_generation_location(ThreeDLocation location);
    void set_payload(ByteBuffer& payload);
    void set_signature(const Signature& signature);
    void set_inline_p2pcd_request(std::list<HashedId3> requests);
    void add_inline_p2_pcd_request(HashedId3 unkown_certificate_digest);
    ByteBuffer convert_for_signing();
    void set_signature(const SomeEcdsaSignature& signature);
    void set_dummy_signature();
    void set_signer_info(const SignerInfo& signer_info);

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
void set_payload(Opaque_t* unsecured, const ByteBuffer& buffer);
ByteBuffer convert_to_payload(vanetza::DownPacket packet);

boost::optional<HashedId8> get_certificate_id(const SecuredMessage::SignerIdentifier&);

} // namespace v3
} // namespace security
} // namespace vanetza

#endif /* SECURED_MESSAGE_HPP_DCBC74AC */

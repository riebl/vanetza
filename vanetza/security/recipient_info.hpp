#ifndef RECIPIENT_INFO_HPP_IENLXEUN
#define RECIPIENT_INFO_HPP_IENLXEUN

#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/public_key.hpp>

namespace vanetza
{
namespace security
{

struct EciesNistP256EncryptedKey
{
    EccPoint v;
    ByteBuffer c;
    ByteBuffer t;
};

typedef boost::variant<EciesNistP256EncryptedKey> Key;

struct RecipientInfo
{
    HashedId8 cert_id;
    Key enc_key;
};

PublicKeyAlgorithm get_type(const RecipientInfo&);

size_t get_size(const RecipientInfo&);
size_t get_size(const std::list<RecipientInfo>&);

void serialize(OutputArchive&, const std::list<RecipientInfo>&);
void serialize(OutputArchive&, const RecipientInfo&);

size_t deserialize(InputArchive&, RecipientInfo&, const SymmetricAlgorithm&);
size_t deserialize(InputArchive&, std::list<RecipientInfo>&, const SymmetricAlgorithm&);

} // namespace security
} // namespace vanetza

#endif /* RECIPIENT_INFO_HPP_IENLXEUN*/

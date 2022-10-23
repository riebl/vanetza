#ifndef CF4C0740_EE9F_493A_A3F5_95DA691E8989
#define CF4C0740_EE9F_493A_A3F5_95DA691E8989

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <cstddef>
#include <future>

namespace vanetza
{
namespace security
{

/// EcdsaSignature specified in TS 103 097 v1.2.1, section 4.2.9
struct EcdsaSignature
{
    EccPoint R;
    ByteBuffer s;
};

class EcdsaSignatureFuture
{
public:
    EcdsaSignatureFuture(std::shared_future<EcdsaSignature>, EcdsaSignature placholder);

    const EcdsaSignature& get() const;
    std::size_t size() const;

private:
    mutable std::shared_future<EcdsaSignature> m_future;
    EcdsaSignature m_placeholder;
};

using SomeEcdsaSignature = boost::variant<EcdsaSignature, EcdsaSignatureFuture>;

/**
 * \brief Extracts binary signature
 * \param signature source for binary signature
 * \return signature as binary
 */
ByteBuffer extract_signature_buffer(const SomeEcdsaSignature& sig);

} // namespace security
} // namespace vanetza

#endif /* CF4C0740_EE9F_493A_A3F5_95DA691E8989 */

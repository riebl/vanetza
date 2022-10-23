#ifndef FA909143_0CE7_4397_A42B_5CDA56AB4716
#define FA909143_0CE7_4397_A42B_5CDA56AB4716

#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/signature.hpp>
#include <cassert>

namespace vanetza
{
namespace security
{

EcdsaSignatureFuture::EcdsaSignatureFuture(std::shared_future<EcdsaSignature> future,
        EcdsaSignature placeholder) :
    m_future(future), m_placeholder(std::move(placeholder))
{
    if (!m_future.valid()) {
        throw std::invalid_argument("EcdsaSignature future has to be valid");
    }
}

const EcdsaSignature& EcdsaSignatureFuture::get() const
{
    assert(m_future.valid());
    const EcdsaSignature& signature = m_future.get();
    assert(signature.s.size() == m_placeholder.s.size());
    assert(signature.R.which() == m_placeholder.R.which());
    assert(get_length(signature.R) == get_length(m_placeholder.R));
    return signature;
}

std::size_t EcdsaSignatureFuture::size() const
{
    return get_length(m_placeholder.R) + m_placeholder.s.size();
}

ByteBuffer extract_signature_buffer(const SomeEcdsaSignature& sig)
{
    struct extraction_visitor : public boost::static_visitor<>
    {
        void operator()(const EcdsaSignature& sig)
        {
            m_buffer = convert_for_signing(sig.R);
            m_buffer.insert(m_buffer.end(), sig.s.begin(), sig.s.end());
        }

        void operator()(const EcdsaSignatureFuture& sig_future)
        {
            const EcdsaSignature& sig = sig_future.get();
            (*this)(sig);
        }

        ByteBuffer m_buffer;
    };

    extraction_visitor visitor;
    boost::apply_visitor(visitor, sig);

    return visitor.m_buffer;
}

} // namespace security
} // namespace vanetza

#endif /* FA909143_0CE7_4397_A42B_5CDA56AB4716 */

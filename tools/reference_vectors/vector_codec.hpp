#ifndef REFERENCE_VECTORS_VECTOR_CODEC_HPP
#define REFERENCE_VECTORS_VECTOR_CODEC_HPP

#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/MAPEM.h>
#include <vanetza/asn1/its/SPATEM.h>
#include <vanetza/asn1/its/SREM.h>
#include <vanetza/asn1/its/SSEM.h>
#include <vanetza/common/byte_buffer.hpp>

#include <stdexcept>
#include <string>

namespace reference_vectors
{

enum class Encoding
{
    Uper,
    Xer
};

namespace detail
{

inline void require_valid(bool ok, const std::string& message, const std::string& error)
{
    if (!ok) {
        throw std::runtime_error(message + ": " + error);
    }
}

template<class T>
vanetza::ByteBuffer transcode_typed(asn_TYPE_descriptor_t& descriptor, const std::string& message, Encoding input, const vanetza::ByteBuffer& bytes)
{
    vanetza::asn1::asn1c_xer_wrapper<T> xer(descriptor);
    vanetza::asn1::asn1c_per_wrapper<T> uper(descriptor);

    std::string error;

    if (input == Encoding::Xer) {
        if (!xer.decode(bytes)) {
            throw std::runtime_error(message + ": XER decode failed");
        }
        require_valid(xer.validate(error), message + ": XER constraint failure", error);
        uper = vanetza::asn1::asn1c_per_wrapper<T>(descriptor, xer.content());
        return uper.encode();
    } else {
        if (!uper.decode(bytes)) {
            throw std::runtime_error(message + ": UPER decode failed");
        }
        require_valid(uper.validate(error), message + ": UPER constraint failure", error);
        xer = vanetza::asn1::asn1c_xer_wrapper<T>(descriptor, uper.content());
        return xer.encode();
    }
}

} // namespace detail

inline vanetza::ByteBuffer transcode(std::string message, Encoding input, const vanetza::ByteBuffer& bytes)
{
    if (message == "mapem") {
        return detail::transcode_typed<MAPEM_t>(asn_DEF_MAPEM, message, input, bytes);
    } else if (message == "spatem") {
        return detail::transcode_typed<SPATEM_t>(asn_DEF_SPATEM, message, input, bytes);
    } else if (message == "srem") {
        return detail::transcode_typed<SREM_t>(asn_DEF_SREM, message, input, bytes);
    } else if (message == "ssem") {
        return detail::transcode_typed<SSEM_t>(asn_DEF_SSEM, message, input, bytes);
    }

    throw std::invalid_argument("unknown message name: " + message);
}

} // namespace reference_vectors

#endif // REFERENCE_VECTORS_VECTOR_CODEC_HPP

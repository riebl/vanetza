#include <vanetza/asn1/support/asn_application.h>
#include <vanetza/asn1/support/asn_internal.h>
#include <vanetza/asn1/support/constraints.h>
#include <vanetza/asn1/support/uper_decoder.h>
#include <vanetza/asn1/support/uper_encoder.h>
#include "asn1c_wrapper.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <iterator>
#include <string>

namespace vanetza
{
namespace asn1
{

static int write_buffer(const void* in, std::size_t size, void* out_void)
{
    assert(out_void != nullptr);
    auto out = static_cast<ByteBuffer*>(out_void);
    std::copy_n(static_cast<const uint8_t*>(in), size, std::back_inserter(*out));
    return 0;
}

static int write_null(const void*, std::size_t, void*)
{
    return 0;
}

void* allocate(std::size_t length)
{
    void* ptr = calloc(1, length);
    if (nullptr == ptr) {
        throw asn1c_exception(asn1c_error(ErrorCode::OutOfMemory));
    }
    return ptr;
}

void free(asn_TYPE_descriptor_t& td, void* t)
{
    if (t != nullptr) {
        ASN_STRUCT_FREE(td, t);
    }
}

void deleter::operator()(void* ptr) const
{
    if (descriptor && ptr) {
        free(*descriptor, ptr);
    }
}

void* copy(asn_TYPE_descriptor_t& td, const void* original)
{
    void* copy = nullptr;
    ByteBuffer buffer;

    asn_enc_rval_t ec;
    ec = oer_encode(&td, const_cast<void*>(original), write_buffer, &buffer);
    if (ec.encoded == -1) {
        throw asn1c_exception(asn1c_error(ErrorCode::EncodeFailed, &td, ec.failed_type));
    }

    asn_dec_rval_t dc;
    dc = oer_decode(0, &td, &copy, buffer.data(), buffer.size());
    if (dc.code != RC_OK) {
        free(td, copy);
        throw asn1c_exception(asn1c_error(ErrorCode::DecodeFailed, &td));
    }

    return copy;
}

bool validate(asn_TYPE_descriptor_t& td, const void* t)
{
    return asn_check_constraints(&td, t, nullptr, nullptr) == 0;
}

bool validate(asn_TYPE_descriptor_t& td, const void* t, std::string& error)
{
    char errbuf[1024];
    std::size_t errlen = sizeof(errbuf);
    bool ok = asn_check_constraints(&td, t, errbuf, &errlen) == 0;
    if (!ok) {
        error = errbuf;
    }
    return ok;
}

int compare(asn_TYPE_descriptor_t& td, const void* a, const void* b)
{
    return td.op->compare_struct(&td, a, b);
}

int print(FILE* stream, asn_TYPE_descriptor_t& td, const void* t)
{
    return asn_fprint(stream, &td, t);
}

std::size_t size_per(asn_TYPE_descriptor_t& td, const void* t, asn1c_error& ec) noexcept
{
    asn_enc_rval_t rval = uper_encode(&td, nullptr, const_cast<void*>(t), write_null, nullptr);
    if (rval.encoded < 0) {
        ec = asn1c_error(ErrorCode::EncodeFailed, &td, rval.failed_type);
        return 0;
    }
    ec = asn1c_error();
    // Caution! rval.encoded are bits not bytes!
    return (rval.encoded + 7) / 8;
}

std::size_t size_per(asn_TYPE_descriptor_t& td, const void* t)
{
    asn1c_error ec;
    std::size_t n = size_per(td, t, ec);
    if (ec) {
        throw asn1c_exception(ec);
    }
    return n;
}

ByteBuffer encode_per(asn_TYPE_descriptor_t& td, const void* t, asn1c_error& ec)
{
    ByteBuffer buffer;
    asn_enc_rval_t rval = uper_encode(&td, nullptr, const_cast<void*>(t), write_buffer, &buffer);
    if (rval.encoded < 0) {
        ec = asn1c_error(ErrorCode::EncodeFailed, &td, rval.failed_type);
        return {};
    }
    ec = asn1c_error();
    return buffer;
}

ByteBuffer encode_per(asn_TYPE_descriptor_t& td, const void* t)
{
    asn1c_error ec;
    ByteBuffer buffer = encode_per(td, t, ec);
    if (ec) {
        throw asn1c_exception(ec);
    }
    return buffer;
}

void decode_per(asn_TYPE_descriptor_t& td, void** t, const void* buffer, std::size_t size, asn1c_error& ec) noexcept
{
    asn_codec_ctx_t ctx {};
    ctx.max_stack_size = ASN__DEFAULT_STACK_MAX;
    asn_dec_rval_t rval = uper_decode_complete(&ctx, &td, t, buffer, size);
    switch (rval.code) {
        case RC_OK:
            ec = asn1c_error();
            break;
        case RC_WMORE:
            ec = asn1c_error(ErrorCode::DecodeIncomplete, &td);
            break;
        default:
            ec = asn1c_error(ErrorCode::DecodeFailed, &td);
            break;
    }
}

bool decode_per(asn_TYPE_descriptor_t& td, void** t, const void* buffer, std::size_t size)
{
    asn1c_error ec;
    decode_per(td, t, buffer, size, ec);
    return !ec;
}

bool decode_per(asn_TYPE_descriptor_t& td, void** t, const ByteBuffer& buffer)
{
    return decode_per(td, t, buffer.data(), buffer.size());
}

std::size_t size_oer(asn_TYPE_descriptor_t& td, const void* t, asn1c_error& ec) noexcept
{
    asn_enc_rval_t rval = oer_encode(&td, const_cast<void*>(t), write_null, nullptr);
    if (rval.encoded < 0) {
        ec = asn1c_error(ErrorCode::EncodeFailed, &td, rval.failed_type);
        return 0;
    }
    ec = asn1c_error();
    // rval.encoded are bytes for OER encoding
    return rval.encoded;
}

std::size_t size_oer(asn_TYPE_descriptor_t& td, const void* t)
{
    asn1c_error ec;
    std::size_t n = size_oer(td, t, ec);
    if (ec) {
        throw asn1c_exception(ec);
    }
    return n;
}

ByteBuffer encode_oer(asn_TYPE_descriptor_t& td, const void* t, asn1c_error& ec)
{
    ByteBuffer buffer;
    asn_enc_rval_t rval = oer_encode(&td, const_cast<void*>(t), write_buffer, &buffer);
    if (rval.encoded < 0) {
        ec = asn1c_error(ErrorCode::EncodeFailed, &td, rval.failed_type);
        return {};
    }
    ec = asn1c_error();
    return buffer;
}

ByteBuffer encode_oer(asn_TYPE_descriptor_t& td, const void* t)
{
    asn1c_error ec;
    ByteBuffer buffer = encode_oer(td, t, ec);
    if (ec) {
        throw asn1c_exception(ec);
    }
    return buffer;
}

void decode_oer(asn_TYPE_descriptor_t& td, void** t, const void* buffer, std::size_t size, asn1c_error& ec) noexcept
{
    asn_codec_ctx_t ctx {};
    ctx.max_stack_size = ASN__DEFAULT_STACK_MAX;
    asn_dec_rval_t rval = oer_decode(&ctx, &td, t, buffer, size);
    switch (rval.code) {
        case RC_OK:
            ec = asn1c_error();
            break;
        case RC_WMORE:
            ec = asn1c_error(ErrorCode::DecodeIncomplete, &td);
            break;
        default:
            ec = asn1c_error(ErrorCode::DecodeFailed, &td);
            break;
    }
}

bool decode_oer(asn_TYPE_descriptor_t& td, void** t, const void* buffer, std::size_t size)
{
    asn1c_error ec;
    decode_oer(td, t, buffer, size, ec);
    return !ec;
}

bool decode_oer(asn_TYPE_descriptor_t& td, void** t, const ByteBuffer& buffer)
{
    return decode_oer(td, t, buffer.data(), buffer.size());
}

std::size_t size_xer(asn_TYPE_descriptor_t& td, const void* t, asn1c_error& ec) noexcept
{
    asn_enc_rval_t rval = xer_encode(&td, const_cast<void*>(t), XER_F_BASIC, write_null, nullptr);
    if (rval.encoded < 0) {
        ec = asn1c_error(ErrorCode::EncodeFailed, &td, rval.failed_type);
        return 0;
    }
    ec = asn1c_error();
    // rval.encoded are bytes for XER encoding
    return rval.encoded;
}

std::size_t size_xer(asn_TYPE_descriptor_t& td, const void* t)
{
    asn1c_error ec;
    std::size_t n = size_xer(td, t, ec);
    if (ec) {
        throw asn1c_exception(ec);
    }
    return n;
}

ByteBuffer encode_xer(asn_TYPE_descriptor_t& td, const void* t, asn1c_error& ec)
{
    ByteBuffer buffer;
    asn_enc_rval_t rval = xer_encode(&td, const_cast<void*>(t), XER_F_BASIC, write_buffer, &buffer);
    if (rval.encoded < 0) {
        ec = asn1c_error(ErrorCode::EncodeFailed, &td, rval.failed_type);
        return {};
    }
    ec = asn1c_error();
    return buffer;
}

ByteBuffer encode_xer(asn_TYPE_descriptor_t& td, const void* t)
{
    asn1c_error ec;
    ByteBuffer buffer = encode_xer(td, t, ec);
    if (ec) {
        throw asn1c_exception(ec);
    }
    return buffer;
}

void decode_xer(asn_TYPE_descriptor_t& td, void** t, const void* buffer, std::size_t size, asn1c_error& ec) noexcept
{
    asn_codec_ctx_t ctx {};
    ctx.max_stack_size = ASN__DEFAULT_STACK_MAX;
    asn_dec_rval_t rval = xer_decode(&ctx, &td, t, buffer, size);
    switch (rval.code) {
        case RC_OK:
            ec = asn1c_error();
            break;
        case RC_WMORE:
            ec = asn1c_error(ErrorCode::DecodeIncomplete, &td);
            break;
        default:
            ec = asn1c_error(ErrorCode::DecodeFailed, &td);
            break;
    }
}

bool decode_xer(asn_TYPE_descriptor_t& td, void** t, const void* buffer, std::size_t size)
{
    asn1c_error ec;
    decode_xer(td, t, buffer, size, ec);
    return !ec;
}

bool decode_xer(asn_TYPE_descriptor_t& td, void** t, const ByteBuffer& buffer)
{
    return decode_xer(td, t, buffer.data(), buffer.size());
}

} // namespace asn1
} // namespace vanetza


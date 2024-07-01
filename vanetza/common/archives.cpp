#include <vanetza/common/archives.hpp>

namespace vanetza
{

InputArchive::InputArchive(InputStream& is) :
    m_stream_buffer(is.rdbuf())
{
}

InputArchive::InputArchive(StreamBuffer& buf) :
    m_stream_buffer(&buf)
{
}

void InputArchive::load_binary(unsigned char* data, std::size_t len)
{
    load_binary(reinterpret_cast<char*>(data), len);
}

void InputArchive::load_binary(char* data, std::size_t len)
{
    std::size_t read_bytes = m_stream_buffer->sgetn(data, len);
    if (read_bytes != len) {
        fail(ErrorCode::IncompleteData);
        throw Exception("incomplete read");
    }
}

char InputArchive::peek_byte()
{
    auto got = m_stream_buffer->sgetc();
    if (got == StreamBuffer::traits_type::eof()) {
        fail(ErrorCode::IncompleteData);
        throw Exception("impossible peek at end of stream");
    } else { 
        return StreamBuffer::traits_type::to_char_type(got);
    }
}

bool InputArchive::is_good() const
{
    return m_error_code == ErrorCode::Ok;
}

InputArchive::ErrorCode InputArchive::error_code() const
{
    return m_error_code;
}

void InputArchive::fail(ErrorCode error_code)
{
    // do not overwrite prior error code except "ok"
    if (m_error_code == ErrorCode::Ok) {
        m_error_code = error_code;
    }
}

std::size_t InputArchive::remaining_bytes()
{
    return m_stream_buffer->in_avail();
}

OutputArchive::OutputArchive(OutputStream& os) :
    m_stream_buffer(os.rdbuf())
{
}

OutputArchive::OutputArchive(StreamBuffer& buf) :
    m_stream_buffer(&buf)
{
}

void OutputArchive::save_binary(const unsigned char* data, std::size_t len)
{
    save_binary(reinterpret_cast<const char*>(data), len);
}

void OutputArchive::save_binary(const char* data, std::size_t len)
{
    std::size_t written_bytes = m_stream_buffer->sputn(data, len);
    if (written_bytes != len) {
        throw Exception("incomplete write");
    }
}

} // namespace vanetza

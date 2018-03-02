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
        throw Exception("incomplete read");
    }
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

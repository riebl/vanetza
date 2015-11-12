#include <vanetza/geonet/header_variant.hpp>

namespace vanetza
{
namespace geonet
{

class HeaderVariantVisitor : public boost::static_visitor<>
{
public:
    HeaderVariantVisitor(OutputArchive& ar) :
        m_archive(ar)
    {
    }

    template<typename T>
    void operator()(const T& header)
    {
        serialize(header, m_archive);
    }

private:
    OutputArchive& m_archive;
};

void serialize(const HeaderVariant& header, OutputArchive& ar)
{
    HeaderVariantVisitor visit(ar);
    boost::apply_visitor(visit, header);
}

class HeaderVariantLengthVisitor : public boost::static_visitor<std::size_t>
{
public:
    template<typename T>
    std::size_t operator()(const T& header)
    {
        return T::length_bytes;
    }
};

std::size_t get_length(const HeaderVariant& header)
{
    HeaderVariantLengthVisitor visit;
    return boost::apply_visitor(visit, header);
}

} // namespace geonet
} // namespace vanetza

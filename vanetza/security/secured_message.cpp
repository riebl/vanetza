#include <vanetza/security/secured_message.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>

namespace vanetza
{
namespace security
{

ItsAid get_its_aid(const SecuredMessage& msg)
{
    struct Visitor : boost::static_visitor<ItsAid>
    {
        ItsAid operator()(const v2::SecuredMessage& msg) const
        {
            return get_its_aid(msg);
        }
    };

    return boost::apply_visitor(Visitor(), msg);
}

std::size_t get_size(const SecuredMessage& msg)
{
    struct Visitor : boost::static_visitor<std::size_t>
    {
        std::size_t operator()(const v2::SecuredMessage& msg) const
        {
            return get_size(msg);
        }
    };

    return boost::apply_visitor(Visitor(), msg);
}

void serialize(OutputArchive& ar, const SecuredMessage& msg)
{
    struct Visitor : boost::static_visitor<void>
    {
        OutputArchive& m_archive;
        Visitor(OutputArchive& ar) : m_archive(ar) {}

        void operator()(const v2::SecuredMessage& msg)
        {
            serialize(m_archive, msg);
        }
    };

    Visitor visitor(ar);
    boost::apply_visitor(visitor, msg);
}

std::size_t deserialize(InputArchive& ar, SecuredMessage& msg)
{
    struct Visitor : boost::static_visitor<std::size_t>
    {
        InputArchive& m_archive;
        Visitor(InputArchive& ar) : m_archive(ar) {}

        std::size_t operator()(v2::SecuredMessage& msg)
        {
            return deserialize(m_archive, msg);
        }
    };

    Visitor visitor(ar);
    return boost::apply_visitor(visitor, msg);
}

PacketVariant get_payload_copy(const SecuredMessage& msg)
{
    struct Visitor : boost::static_visitor<PacketVariant>
    {
        PacketVariant operator()(const v2::SecuredMessage& msg) const
        {
            return msg.payload.data;
        }
    };

    return boost::apply_visitor(Visitor {}, msg);
}

} // namespace security
} // namespace vanetza

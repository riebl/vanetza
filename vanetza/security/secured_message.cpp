#include <vanetza/security/secured_message.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>

namespace vanetza
{
namespace security
{

SecuredMessageView::SecuredMessageView(const SecuredMessage& msg) :
    m_variant(msg)
{
}

struct ItsAidVisitor : boost::static_visitor<ItsAid>
{
    ItsAid operator()(const v2::SecuredMessage& msg) const
    {
        return get_its_aid(msg);
    }

    ItsAid operator()(const v3::SecuredMessage& msg) const
    {
        return msg.its_aid();
    }
};

ItsAid get_its_aid(const SecuredMessage& msg)
{
    return boost::apply_visitor(ItsAidVisitor(), msg);
}

ItsAid get_its_aid(const SecuredMessageView& msg)
{
    return boost::apply_visitor(ItsAidVisitor(), msg);
}

std::size_t get_size(const SecuredMessage& msg)
{
    struct Visitor : boost::static_visitor<std::size_t>
    {
        std::size_t operator()(const v2::SecuredMessage& msg) const
        {
            return get_size(msg);
        }

        std::size_t operator()(const v3::SecuredMessage& msg) const
        {
            return msg.size();
        }
    };

    return boost::apply_visitor(Visitor(), msg);
}

struct SerializeVisitor : boost::static_visitor<void>
{
    OutputArchive& m_archive;
    SerializeVisitor(OutputArchive& ar) : m_archive(ar) {}

    void operator()(const v2::SecuredMessage& msg)
    {
        serialize(m_archive, msg);
    }

    void operator()(const v3::SecuredMessage& msg)
    {
        serialize(m_archive, msg);
    }
};

void serialize(OutputArchive& ar, const SecuredMessage& msg)
{
    SerializeVisitor visitor { ar };
    boost::apply_visitor(visitor, msg);
}

void serialize(OutputArchive& ar, const SecuredMessageView& msg)
{
    SerializeVisitor visitor { ar };
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

        std::size_t operator()(v3::SecuredMessage& msg)
        {
            return deserialize(m_archive, msg);
        }
    };

    Visitor visitor(ar);
    return boost::apply_visitor(visitor, msg);
}

struct PayloadCopyVisitor : boost::static_visitor<PacketVariant>
{
    PacketVariant operator()(const v2::SecuredMessage& msg) const
    {
        return msg.payload.data;
    }

    PacketVariant operator()(const v3::SecuredMessage& msg) const
    {
        return msg.payload();
    }
};

PacketVariant get_payload_copy(const SecuredMessage& msg)
{
    return boost::apply_visitor(PayloadCopyVisitor {}, msg);
}

PacketVariant get_payload_copy(const SecuredMessageView& msg)
{
    return boost::apply_visitor(PayloadCopyVisitor {}, msg);
}

} // namespace security
} // namespace vanetza

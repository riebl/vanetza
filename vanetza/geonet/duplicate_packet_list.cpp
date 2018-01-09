#include <vanetza/geonet/duplicate_packet_list.hpp>
#include <cassert>

namespace vanetza
{
namespace geonet
{

DuplicatePacketList::DuplicatePacketList(unsigned elements) :
    m_elements(elements)
{
    assert(m_elements.size() == 0);
}

bool DuplicatePacketList::check(SequenceNumber sn)
{
    ListElement* element = find(sn);
    if (element) {
        ++element->counter;
        return true;
    } else {
        m_elements.push_back(ListElement { sn });
        return false;
    }
}

unsigned DuplicatePacketList::counter(SequenceNumber sn) const
{
    for (auto& element : m_elements) {
        if (element.sequence_number == sn) {
            return element.counter;
        }
    }
    return 0;
}

DuplicatePacketList::ListElement* DuplicatePacketList::find(SequenceNumber sn)
{
    for (auto& element : m_elements) {
        if (element.sequence_number == sn) {
            return &element;
        }
    }
    return nullptr;
}

DuplicatePacketList::ListElement::ListElement(SequenceNumber sn) :
    sequence_number(sn), counter(1)
{
}

} // namespace geonet
} // namespace vanetza

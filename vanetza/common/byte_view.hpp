#ifndef BYTE_VIEW_HPP_TXN2ISMB
#define BYTE_VIEW_HPP_TXN2ISMB

#include <vanetza/common/byte_buffer.hpp>
#include <boost/core/pointer_traits.hpp>
#include <boost/range/iterator_range.hpp>
#include <iterator>
#include <memory>

namespace vanetza
{

// forward declaration
class ByteBufferConvertible;

class byte_view_iterator
{
public:
    using iterator_category = std::random_access_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using value_type = std::uint8_t;
    using pointer = const value_type*;
    using reference = const value_type&;

    byte_view_iterator() = default;
    explicit byte_view_iterator(pointer p) : m_iterator(p) {}
    explicit byte_view_iterator(const ByteBuffer::const_iterator& it) : m_iterator(boost::to_address(it)) {}

    constexpr value_type operator*() const
    {
        return *m_iterator;
    }

    constexpr byte_view_iterator& operator++()
    {
        ++m_iterator;
        return *this;
    }

    constexpr byte_view_iterator operator++(int)
    {
        byte_view_iterator it = *this;
        ++m_iterator;
        return it;
    }

    constexpr byte_view_iterator& operator--()
    {
        --m_iterator;
        return *this;
    }

    constexpr byte_view_iterator operator--(int)
    {
        byte_view_iterator it = *this;
        --m_iterator;
        return it;
    }

    constexpr byte_view_iterator& operator+=(difference_type n)
    {
        m_iterator += n;
        return *this;
    }

    constexpr byte_view_iterator& operator-=(difference_type n)
    {
        m_iterator -= n;
        return *this;
    }

    constexpr difference_type operator-(const byte_view_iterator& o) const
    {
        return m_iterator - o.m_iterator;
    }

    constexpr reference operator[](difference_type n)
    {
        return m_iterator[n];
    }

    constexpr bool operator==(const byte_view_iterator& o) const
    {
        return m_iterator == o.m_iterator;
    }

    constexpr bool operator!=(const byte_view_iterator& o) const
    {
        return m_iterator != o.m_iterator;
    }

    constexpr bool operator>(const byte_view_iterator& o) const
    {
        return m_iterator > o.m_iterator;
    }

    constexpr bool operator<(const byte_view_iterator& o) const
    {
        return m_iterator < o.m_iterator;
    }

    constexpr bool operator>=(const byte_view_iterator& o) const
    {
        return m_iterator >= o.m_iterator;
    }

    constexpr bool operator<=(const byte_view_iterator& o) const
    {
        return m_iterator <= o.m_iterator;
    }

    constexpr pointer raw() const
    {
        return m_iterator;
    }

private:
    pointer m_iterator = nullptr;
};

constexpr byte_view_iterator operator+(byte_view_iterator::difference_type n, byte_view_iterator it)
{
    return it += n;
}

constexpr byte_view_iterator operator+(byte_view_iterator it, byte_view_iterator::difference_type n)
{
    return it += n;
}

/**
 * byte_view_range fulfills the range concept and provides a view of contiguous bytes
 * \note private inheritance is used to prevent object slicing
 */
class byte_view_range : private boost::iterator_range<byte_view_iterator>
{
    using range_type = boost::iterator_range<byte_view_iterator>;

public:
    using value_type = byte_view_iterator::value_type;
    using pointer = byte_view_iterator::pointer;

    /**
     * Construct new view from iterator pair.
     * \param begin begin iterator of view
     * \param end end iterator of view
     * \note View is valid as long as passed iterators are valid
     */
    byte_view_range(const ByteBuffer::const_iterator&, const ByteBuffer::const_iterator&);
    byte_view_range(const byte_view_iterator&, const byte_view_iterator&);

    /**
     * Create new view and take ownership of passed buffer
     * \param buffer pass buffer via rvalue
     * \note View is valid without limitation
     */
    explicit byte_view_range(ByteBuffer&&);

    /**
     * Get pointer to start of contiguous buffer memory
     * \return pointer (can be nullptr)
     */
    ByteBuffer::const_pointer data() const;

    /**
     * Access a certain byte within range
     * \param pos byte position within [0; size()[
     * \note Override implementation by boost::iterator_range
     * \return byte value
     */
    value_type operator[](size_type) const;

    // make several funtions from boost::iterator_range accessible
    using range_type::size;
    using range_type::begin;
    using range_type::end;

private:
    ByteBuffer buffer;
};

/**
 * Create a byte view based on various byte buffer representations.
 * View is valid at least as long as passed arguments are valid
 * \param byte buffer or byte buffer convertible
 * \return byte view representing passed byte buffer
 */
byte_view_range create_byte_view(ByteBuffer&&);
byte_view_range create_byte_view(const ByteBuffer&);
byte_view_range create_byte_view(const ByteBufferConvertible&);

} // namespace vanetza

#endif /* BYTE_VIEW_HPP_TXN2ISMB */


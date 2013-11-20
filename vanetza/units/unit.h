#ifndef UNIT_H_XY3QBUPL
#define UNIT_H_XY3QBUPL

#define VANETZA_UNIT(_tmpl, _unit, _alias) \
    typedef _tmpl<_unit> _alias; \
    template<> struct unit_trait<_unit> { typedef _alias quantity_type; };

template<typename FROM, typename TO, typename T>
struct conversion_helper;

template<typename UNIT>
struct unit_trait;

template<typename T, typename UNIT>
typename unit_trait<UNIT>::quantity_type operator%(T numeric, UNIT)
{
    return typename unit_trait<UNIT>::quantity_type(numeric);
}

#endif /* UNIT_H_XY3QBUPL */


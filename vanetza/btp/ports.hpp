#ifndef PORTS_HPP_T2IEFSSC
#define PORTS_HPP_T2IEFSSC

#include <vanetza/common/byte_order.hpp>

namespace vanetza
{
namespace btp
{

typedef uint16be_t port_type;

namespace ports
{

// Port numbers according to ETSI TS 103 248 v2.1.1 (2021-08)
static const port_type CAM = host_cast<uint16_t>(2001);
static const port_type DENM = host_cast<uint16_t>(2002);
static const port_type TOPO = host_cast<uint16_t>(2003);
static const port_type SPAT = host_cast<uint16_t>(2004);
static const port_type SAM = host_cast<uint16_t>(2005);
static const port_type IVIM = host_cast<uint16_t>(2006);
static const port_type SREM = host_cast<uint16_t>(2007);
static const port_type SSEM = host_cast<uint16_t>(2008);
static const port_type CPM = host_cast<uint16_t>(2009);
static const port_type EVCSN_POI = host_cast<uint16_t>(2010);
static const port_type TRM = host_cast<uint16_t>(2011);
static const port_type TCM = host_cast<uint16_t>(2011);
static const port_type VDRM = host_cast<uint16_t>(2011);
static const port_type VDPM = host_cast<uint16_t>(2011);
static const port_type EOFM = host_cast<uint16_t>(2011);
static const port_type EV_RSR = host_cast<uint16_t>(2012);
static const port_type RTCMEM = host_cast<uint16_t>(2013);
static const port_type CTLM = host_cast<uint16_t>(2014);
static const port_type CRLM = host_cast<uint16_t>(2015);
static const port_type EC_AT_REQUEST = host_cast<uint16_t>(2016);
static const port_type MCDM = host_cast<uint16_t>(2017);
static const port_type VAM = host_cast<uint16_t>(2018);
static const port_type IMZM = host_cast<uint16_t>(2019);

} // namespace ports

} // namespace btp
} // namespace vanetza

#endif /* PORTS_HPP_T2IEFSSC */


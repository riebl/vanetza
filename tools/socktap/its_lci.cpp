#include "its_lci.hpp"
#include <vanetza/btp/ports.hpp>
#include <vanetza/asn1/cam.hpp>
#include <vanetza/asn1/packet_visitor.hpp>
#include <vanetza/facilities/cam_functions.hpp>
#include <boost/units/cmath.hpp>
#include <boost/units/systems/si/prefixes.hpp>
#include <chrono>
#include <exception>
#include <functional>
#include <iostream>

// This is a very simple CA application sending CAMs at a fixed rate.

using namespace vanetza;
using namespace vanetza::facilities;
using namespace std::chrono;

ITC_LCI_Application::ITC_LCI_Application(PositionProvider& positioning, Runtime& rt) :
    positioning_(positioning), runtime_(rt), cam_interval_(seconds(1))
{
    int i = 0;
    printf("hellow %d", i);
}

void ITC_LCI_Application::indicate(const DataIndication& indication, UpPacketPtr packet)
{
   
}
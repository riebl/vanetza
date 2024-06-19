#ifndef ITC_LCI_HPP
#define ITC_LCI_HPP

#include "application.hpp"
#include <vanetza/common/clock.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/runtime.hpp>

class ITC_LCI_Application : public Application
{
public:
    ITC_LCI_Application(vanetza::PositionProvider& positioning, vanetza::Runtime& rt);
    PortType port() override;
    void indicate(const DataIndication&, UpPacketPtr) override;
    
private:
    
    vanetza::PositionProvider& positioning_;
    vanetza::Runtime& runtime_;
    vanetza::Clock::duration cam_interval_;
};

#endif
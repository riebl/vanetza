#include "nfiniity_cube_evk.hpp"
#include "nfiniity_cube_evk_link.hpp"

namespace po = boost::program_options;

void vanetza::nfiniity::add_cube_evk_options(po::options_description& options)
{
    options.add_options()
        ("cube-ip", po::value<std::string>()->default_value("127.0.0.1"), "cube evk's ip address")
        ("cube-tx-port", po::value<unsigned>()->default_value(CubeEvkLink::default_tx_port), "transmit frames to cube evk on this port")
        ("cube-rx-port", po::value<unsigned>()->default_value(CubeEvkLink::default_rx_port), "receive frames from cube evk on this port")
    ;
}

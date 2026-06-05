#include "nfiniity_cube_evk.hpp"

namespace po = boost::program_options;

void vanetza::nfiniity::add_cube_evk_options(po::options_description& options)
{
    options.add_options()
        ("cube-ip", po::value<std::string>()->default_value("127.0.0.1"), "cube evk's ip address")
        ("cube-tx-port", po::value<unsigned>()->default_value(33210), "cube evk UDP transmit port")
        ("cube-rx-port", po::value<unsigned>()->default_value(33211), "cube evk UDP receive port")
    ;
}

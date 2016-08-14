#include <fstream>
#include <sstream>
#include <cstdlib>
#include <vanetza/geonet/position_vector.hpp>
#include <vanetza/geonet/router.hpp>
#include <time.h>
#include <vanetza/geonet/units.hpp>
#include<math.h>
#include<vanetza/units/angle.hpp>
#include<vanetza/geonet/areas.hpp>
#include <boost/units/systems/si/plane_angle.hpp>
#include <vanetza/geonet/timestamp.hpp>
#include <vanetza/units/time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <vanetza/units/velocity.hpp>
#include <vector>

//For RTS
//Added for converting the time difference to time_point
#include <boost/asio/io_service.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <vanetza/common/runtime.hpp>
#include <chrono>
#include<vanetza/common/clock.hpp>

// count of fields in NMEA RMC data sentence
#define FIELD_COUNT 13


class CGpsData {  
  
private:

	//member variable to store name of file containing fake GPS Data
// 	std::string m_filePath;

	//member variable to store long position vector
	vanetza::geonet::LongPositionVector lpv_;
	
	//member variable to store GeodeticPosition
	vanetza::geonet::GeodeticPosition pos;
	
	//member variable to store latitude in GeoAngle format
	vanetza::units::GeoAngle m_latitude;
	
	//member variable to store longitude in GeoAngle format
	vanetza::units::GeoAngle m_longitude;
	
	//member variable to store heading 
	vanetza::units::GeoAngle m_heading;
	
	//member variable to store speed
	vanetza::units::Velocity m_speed;
	
	
	

public:
	CGpsData();

	/**
	 * Set the name of the file to be used for storing fake GPS data.
	 * The exact interpretation of the name depends on the implementation
	 * of the component.
	 *
	 * @param name the file to be used
	 */
// 	void setFileName(std::string filePathFromTerminal);

	//Function to read GPS data from a file
	void readFakeGPSData(vanetza::geonet::Router &routerObj);

	virtual ~CGpsData();

	//Function to update the LongPositionVector with values read from the GPS fake data file
	void updateLPV(double latitude, double longitude, vanetza::geonet::Timestamp timestampObj, double headingFromNMEA, double speedFromNMEA);

	// Function to convert double to geo angle values for latitude and longitude
	void convertAngleValues(double latitude, double longitude, vanetza::geonet::GeodeticPosition &position);
	
	
	static std::string filePathFromTerminal;
};

// Function to process date and time to create posix time object
void convertDateAndTime(std::string date, std::string time, std::string &date_time);

// Function to fetch fields of a NMEA RMC sentence as streams
void fetch_NMEA_RMC_Fields(std::string &input_line, std::vector<std::stringstream*> &fieldStream);


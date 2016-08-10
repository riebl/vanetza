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

#include <sys/types.h>
#include <dirent.h>

#include <boost/asio/steady_timer.hpp>

// count of fields in NMEA RMC data sentence
#define FIELD_COUNT 13

#include <vector>


// Added for Live gps data

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <termios.h>
#include <errno.h>
#include <gps.h>


class CGpsData {  
  
private:

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
	
	//member variable to store steady_timer object referrence
	boost::asio::steady_timer& timer_;
	
	// variable to store time duration for scheduling
	int m_timeDuration;
	
	//pointer to router object of RouterContext class
	vanetza::geonet::Router* m_p_routerObj;
	
	// indicator to select live GPS data for broadcasting
	bool m_gpsDongleStatus;
	
	// indicator to show connection with Gps dongle
	bool m_connectionStatus;
	
	// variable containing a single NMEA RMC sentence whose position data is to be broadcasted
	std::string m_inputLine;
	
	// To keep track of Position data to be broadcasted from the lines of gps data file
	
	/*static long long unsigned int m_lineCount;*/
	
	static unsigned long long int m_lineCount;
	
	// database containing NMEA RMC sentences from the fake data file	
	std::vector<std::string> m_database;
	
	// vector contating difference in timestamps of NMEA RMC sentences
	std::vector<double> m_timeStamp; 
	
	// vector contating difference in timestamps of NMEA RMC sentences
	std::vector<double> m_timeDifference; 
	
	std::vector<double>::iterator it;
	
	std::string m_filePath;
	
	struct gps_data_t gps_data;

public:
  
  	CGpsData(boost::asio::steady_timer&, vanetza::geonet::Router* routerObj, bool liveGPS, std::string filePathFromTerminal);

	//Function to read GPS data from a file
	void readFakeGPSData();
	
	void createPositionDatabase();	
	
	void readLiveGPSData();

	virtual ~CGpsData();

	//Function to update the LongPositionVector with values read from the GPS fake data file
	void updateLPV(double latitude, double longitude, vanetza::geonet::Timestamp timestampObj, double headingFromNMEA, double speedFromNMEA);

	// Function to convert double to geo angle values for latitude and longitude
	void convertAngleValues(double latitude, double longitude, vanetza::geonet::GeodeticPosition &position);
		
	std::string filePathFromTerminal;
	
	void on_Timer_FakeGPSData(const boost::system::error_code& ec);
	
 	void schedule_FakeGpsData();
	
	void schedule_LiveGpsData();
	
	void on_Timer_LiveGPSData(const boost::system::error_code& ec);
	
 	void selectPositionProviderToUpdateRouter();
// 	
 	void processGPSDataAndUpdateRouter(std::string &input_line);
	
	void updateRouterWithLiveGpsData();
	
};

// Function to process date and time to create posix time object
void convertDateAndTime(std::string date, std::string time, std::string &date_time);




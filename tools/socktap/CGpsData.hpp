#include <fstream>
#include <sstream>
#include <cstdlib>
#include <vanetza/geonet/position_vector.hpp>
#include <vanetza/geonet/router.hpp>
#include <time.h>
#include <vanetza/geonet/units.hpp>
#include <math.h>
#include <vanetza/units/angle.hpp>
#include <vanetza/geonet/areas.hpp>
#include <boost/units/systems/si/plane_angle.hpp>
#include <vanetza/geonet/timestamp.hpp>
#include <vanetza/units/time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <vanetza/units/velocity.hpp>
#include <vector>
#include <boost/asio/io_service.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <vanetza/common/runtime.hpp>
#include <chrono>
#include <vanetza/common/clock.hpp>
#include <sys/types.h>
#include <dirent.h>
#include <boost/asio/steady_timer.hpp>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <termios.h>
#include <errno.h>
#include <gps.h>

// count of fields in NMEA RMC data sentence
#define FIELD_COUNT 13

class CGpsData {  
private:

	//member variable to store long position vector
	vanetza::geonet::LongPositionVector lpv_;
	
	//member variable to store GeodeticPosition
	vanetza::geonet::GeodeticPosition m_pos;
	
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
	
	//variable to store time duration for scheduling
	int m_timeDuration;
	
	//pointer to router object of RouterContext class
	vanetza::geonet::Router* m_p_routerObj;
	
	//indicator to select live GPS data for broadcasting
	bool m_gpsDongleStatus;
	
	//indicator to show connection with Gps dongle
	bool m_connectionStatus;
	
	//variable containing a single NMEA RMC sentence whose position data is to be broadcasted
	std::string m_inputLine;
	
	//To keep track of Position data to be broadcasted from the lines of GPS data file
	static unsigned long long int m_lineCount;
	
	//Database containing NMEA RMC sentences from the fake data file	
	std::vector<std::string> m_database;
	
	//Vector contating difference in timestamps of NMEA RMC sentences
	std::vector<double> m_timeStamp; 
	
	//Vector contating difference in timestamps of NMEA RMC sentences
	std::vector<double> m_timeDifference; 
	
	//Iterator for vector of double type
	std::vector<double>::iterator it;
	
	//Variable to store location of text file containing GPS data
	std::string m_filePath;
	
	//gps_data_t structure to grant access to GPS data
	struct gps_data_t gps_data;
	
	//variable to type define timestamp for live gps data
	typedef long double timestamp_t;
public:	
	// Constructor of the class	  
  	CGpsData(boost::asio::steady_timer& timer, vanetza::geonet::Router* routerObj, bool liveGPS, std::string filePathFromTerminal);

	//Function to read GPS data from a file
	void readFakeGPSData();
	
	//Function to create NMEA RMC sentence and time difference databases
	void createPositionDatabase();	
	
	//Function to read live GPS data from a dongle
	void readLiveGPSData();

	//Function to update the LongPositionVector with values read from the GPS fake data file
	void updateLPV(double latitude, double longitude, vanetza::geonet::Timestamp timestampObj, double headingFromNMEA, double speedFromNMEA);	
	
	//Function to expire timer and schedule processing of GPS data from text file
	void schedule_FakeGpsData();
	
	//Function to process GPS data stored in text file and update router
	void on_Timer_FakeGPSData(const boost::system::error_code& ec);
	
	//Function to expire timer and schedule processing of live GPS data from dongle
	void schedule_LiveGpsData();
	
	//Function to process live GPS data from dongle
	void on_Timer_LiveGPSData(const boost::system::error_code& ec);
	
	//Function to switch between live and stored GPS data
	void selectPositionProviderToUpdateRouter();
	
	//Function to process GPS data and update the LPV object
	void processGPSDataAndUpdateLPV(std::string &input_line);
	
	//Function to update LPV and router object with live GPS data from dongle
	void updateRouterWithLiveGpsData();
	
	//Function for converting timestamp_t to Timestamp object
	vanetza::geonet::Timestamp convert(timestamp_t gpstime) const;
	
	//Destructor of the class
	virtual ~CGpsData();
};

// Function to convert double to geo angle values for latitude and longitude
void convertAngleValues(double &latitude, double &longitude);

// Function to process date and time to create posix time object
void convertDateAndTime(std::string date, std::string time, std::string &date_time);




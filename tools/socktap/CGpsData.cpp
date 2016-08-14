#include <iostream>
#include <fstream>

using namespace std;

#include "CGpsData.hpp"

unsigned long long int CGpsData::m_lineCount;

CGpsData::CGpsData(boost::asio::steady_timer& timer,
		vanetza::geonet::Router* routerObj, bool liveGPS,
		string filePathFromTerminal) :
		timer_(timer) {

	m_p_routerObj = routerObj;
	m_gpsDongleStatus = liveGPS;
	m_inputLine = "";
	lpv_.position_accuracy_indicator = false;
	m_timeDuration = 5000;
	m_filePath = filePathFromTerminal;
	m_connectionStatus = false;
	
	// gps_open implementation
	
	//gps_open("localhost", "2947", &gps_data);
}

void CGpsData::selectPositionProviderToUpdateRouter() {
	if (m_gpsDongleStatus) {
		readLiveGPSData();
	} else {
		readFakeGPSData();
	}
}

// Function to read GPS data from file, populate LPV object and update router
void CGpsData::readFakeGPSData() {

	if (m_lineCount < 1) {
		createPositionDatabase();
	}

	schedule_FakeGpsData();
}

void CGpsData::createPositionDatabase() {
	// variable to store ifstream obj of GPS data file
	ifstream gpsFakeDataFile;

	// string variables created to store temporary data for processing
	string input_line;

	//variables needed for conversion of timestamp to milliseconds
	double conv_time, hrs, mins, seconds, milliSeconds;

	stringstream fieldStream[FIELD_COUNT];

	//to keep count of number of delimiter and fields in a line
	unsigned int fieldCount, delimCount;

	//to show an error in GPRMC sentence at a paticular line in the file
	unsigned long long int line_number = 0;

	//string variables created to store temporary data for processing
	string date, time, date_time, str_lat, str_long, speed, str_N_S, str_E_W;

	bool status_RMC_Sentence;

	// Open the file containing fake GPS NMEA sentences
	gpsFakeDataFile.open(m_filePath);

	if ((gpsFakeDataFile.is_open()) && (!gpsFakeDataFile.eof())) {

		// populate database with all lines and timestamp vector with timestamp values

		while (getline(gpsFakeDataFile, input_line)) {
			fieldCount = 0;
			delimCount = 0;
			line_number++;

			string currentLine = input_line;
			//stream for splitting
			istringstream buf(currentLine);

			getline(buf, currentLine, ',');

			//check if the NMEA sentence is GPRMC
			if (currentLine == "$GPRMC") {
				// count the number of delimiters in the NMEA sentence
				for (unsigned int i = 0; i < input_line.size(); i++) {
					if (input_line[i] == ',')
						delimCount++;
				}

				// check if field count is as expected(13)
				if (delimCount == FIELD_COUNT - 1) {

					currentLine = input_line;

					//stream for splitting
					istringstream streamOfLine(currentLine);

					while (getline(streamOfLine, currentLine, ',')) {
						fieldStream[fieldCount++] << currentLine;
					}

					str_lat = fieldStream[3].str();
					str_long = fieldStream[5].str();
					time = fieldStream[1].str();
					date = fieldStream[9].str();
					str_N_S = fieldStream[4].str();
					str_E_W = fieldStream[6].str();
					//heading = fieldStream[10].str();
					speed = fieldStream[8].str();

					/* If any value is absent in the GPRMC sentence, it is not valid.
					 */

					status_RMC_Sentence = (str_lat.empty() || str_long.empty()
							|| time.empty() || date.empty() || str_N_S.empty()
							|| str_E_W.empty() || speed.empty());

					if (!status_RMC_Sentence)

					{
						//cout << "Added RMC Sentence : " << input_line << " to DB." << endl;		  
						m_database.push_back(input_line);

						//Conversion of timestamp into milliseconds
						hrs = stod(time.substr(0, 2));
						mins = stod(time.substr(2, 2));
						seconds = stod(time.substr(4, 2));
						milliSeconds = stod(time.substr(6, 4));
						conv_time = (hrs * 60 * 60 + mins * 60 + seconds) * 1000
								+ milliSeconds * 1000;

						// Add timestamp in milliSeconds to vector
						m_timeStamp.push_back(conv_time);
					}

				} else {
					cout
							<< "ERROR in processing timestamp - No. of fields in the line "
							<< line_number << " is " << ++delimCount
							<< ". But expected no. of fields: " << FIELD_COUNT
							<< endl;
				}
			}

			//clear fieldStream for reuse
			for (unsigned int i = 0; i < FIELD_COUNT; i++)
				fieldStream[i].str(string());
		}

		// calcuate timedifference and update timeDiffVector
		for (it = m_timeStamp.begin(); it != m_timeStamp.end() - 1; ++it) {
			m_timeDifference.push_back(*(it + 1) - *it);
		}

		//close the file containing fake data
		gpsFakeDataFile.close();
	} else
		cout << "failed to open file from location : " << m_filePath
				<< endl;
}

void CGpsData::processGPSDataAndUpdateLPV(string &input_line) {
	unsigned int delimCount = 0;
	unsigned int fieldCount = 0;
	stringstream fieldStream[FIELD_COUNT];

	string currentLine = input_line;

	//cout << input_line << endl;

	//string variables created to store temporary data for processing
	string date, time, date_time, str_lat, str_long, heading, speed, str_N_S,
			str_E_W;

	//double variables which will be passed to updateLPV function
	double headingFromNMEA, speedFromNMEA, latitudeFROMNMEA, longitudeFROMNMEA;

	//stream for splitting
	istringstream streamOfLine(input_line);
	istringstream buf(currentLine);

	getline(buf, currentLine, ',');

	//split and assign fields on NMEA RMC sentence to streams
	while (getline(streamOfLine, input_line, ',')) {
		fieldStream[fieldCount++] << input_line;
	}

	//Extracting the field values and assigning them to respective variables
	str_lat = fieldStream[3].str();
	str_long = fieldStream[5].str();
	time = fieldStream[1].str();
	date = fieldStream[9].str();
	str_N_S = fieldStream[4].str();
	str_E_W = fieldStream[6].str();

	//Convert string to double values
	latitudeFROMNMEA = stod(str_lat.c_str());
	longitudeFROMNMEA = stod(str_long.c_str());

	//Compute negative value if South
	if (str_N_S == "S")
		latitudeFROMNMEA = latitudeFROMNMEA * (-1);

	//Compute negative value if West
	if (str_E_W == "W")
		longitudeFROMNMEA = longitudeFROMNMEA * (-1);

	//Extract heading from NMEA RMC sentence
	heading = fieldStream[10].str();
	if (heading.length() == 0)
		heading = "0";

	//Convert to double
	headingFromNMEA = stod(heading.c_str());

	//Extract speed from NMEA RMC sentence
	speed = fieldStream[8].str();
	speedFromNMEA = stod(speed.c_str());

	cout << "Broadcasted position has latitude : " << latitudeFROMNMEA
			<< " and longitude : " << longitudeFROMNMEA << " heading : "
			<< headingFromNMEA << " speed : " << speedFromNMEA << endl << endl;

	//format date and time read from NMEA RMC sentence to construct a posix_time object
	convertDateAndTime(date, time, date_time);

	//instantiate posix time object
	boost::posix_time::ptime ptimeObj;
	ptimeObj = boost::posix_time::from_iso_string(date_time);

	//Construct Timestamp object using posix time object
	vanetza::geonet::Timestamp timestampObj(ptimeObj);
	
	convertAngleValues(latitudeFROMNMEA, longitudeFROMNMEA);

	//update the member variables of long position vector
	updateLPV(latitudeFROMNMEA, longitudeFROMNMEA, timestampObj,
			headingFromNMEA, speedFromNMEA);
}

/**
 * Function to set delimiter for the current line
 * @param lineFromFile - current line read from the file
 * @param c			   - character to hold delimiter
 */

void CGpsData::updateLPV(double latitude, double longitude,
		vanetza::geonet::Timestamp timestampObj, double headingFromNMEA,
		double speedFromNMEA) {
	
	//latitude converted to degrees
	m_latitude = latitude * vanetza::units::degree;
	
	//latitude in degrees assgined to variable of geodetic position object
	m_pos.latitude = m_latitude;

	//longitude converted to degrees
	m_longitude = longitude * vanetza::units::degree;
	
	//latitude in degrees assgined to variable of geodetic position object
	m_pos.longitude = m_longitude;

	// static cast to convert to type geo_angle_i32t
	lpv_.latitude = static_cast<vanetza::geonet::geo_angle_i32t>(m_pos.latitude);
	lpv_.longitude = static_cast<vanetza::geonet::geo_angle_i32t>(m_pos.longitude);
	
	 // update position_accuracy_indicator as true as long as there is data to be read from file/GPS reciever
	lpv_.position_accuracy_indicator = true;

	// update the timestamp of the longPositionVector
	lpv_.timestamp = timestampObj;

	// Converted to degrees as it specifies the direction
	m_heading = headingFromNMEA * vanetza::units::degree;

	//Static cast to convert the degrees to heading_u16t
	lpv_.heading = static_cast<vanetza::geonet::heading_u16t>(m_heading);

	//Code for updating speed
	m_speed = speedFromNMEA * vanetza::units::si::meter_per_second;

	//Static cast to convert speed to speed_u15t
	lpv_.speed = static_cast<vanetza::geonet::LongPositionVector::speed_u15t>(m_speed);
	
}


void CGpsData::on_Timer_FakeGPSData(const boost::system::error_code& ec) {
	if (boost::asio::error::operation_aborted != ec) {

		if (m_lineCount < m_database.size()) {
			processGPSDataAndUpdateLPV (m_database[m_lineCount]);
			m_p_routerObj->update(lpv_);
			timer_.expires_from_now(std::chrono::milliseconds(m_timeDuration));

			m_lineCount++;

			if (m_lineCount == m_database.size())
				cout
						<< "End of GPS fake data file reached. GPS data unavailable."
						<< endl;
		}
		schedule_FakeGpsData();
	}
}

void CGpsData::schedule_FakeGpsData() {
	if (m_lineCount < m_timeDifference.size()) {
		m_timeDuration = m_timeDifference[m_lineCount];
	}

	//timer_.expires_from_now(std::chrono::milliseconds(m_timeDuration));
	timer_.async_wait(
			std::bind(&CGpsData::on_Timer_FakeGPSData, this,
					std::placeholders::_1));
}

/**************************************** CODE FOR UPDATING ROUTER USING LIVE GPS DATA ***************************************/

void CGpsData::readLiveGPSData() {


}




/*
 * Function to convert latitude and longitude values to degrees
 */
void convertAngleValues(double &latitude, double &longitude) {
	double deg, mins, sec;
	double divisorValue = 100.00;

	// Extracting and formatting time data
	mins = modf(latitude, &divisorValue);
	deg = int(latitude);
	double deg1 = deg / 100;
	deg = int(deg1);
	double difference = (deg1 - deg) * 100;
	mins = mins + difference;
	latitude = deg + (mins / 60);
	divisorValue = 1000.00;
	mins = modf(longitude, &divisorValue);
	deg = int(longitude);
	deg1 = deg / 100;
	deg = int(deg1);
	difference = (deg1 - deg) * 100;
	mins = mins + difference;
	longitude = deg + (mins / 60);
}

/*
 *Function to format date and time read from NMEA RMC format to construct a posix_time object
 */
void convertDateAndTime(string date, string time, string &date_time) {
// Temporary variables to process date and time
	string dd, mm, yyyy, hh, mins, ss;
	int intDate, intMonths, intYear, intMonthAndYear, intHour;

	// Extract and format date
	intDate = stoi(date);
	intMonthAndYear = intDate % 10000;
	intDate = intDate / 10000;
	intMonths = intMonthAndYear / 100;

	intYear = intMonthAndYear % 100;
	intYear = 2000 + intYear;

	dd = to_string(intDate);
	mm = to_string(intMonths);
	yyyy = to_string(intYear);

	// if month
	if (mm.length() == 1)
		mm = "0" + mm;

	if (dd.length() == 1)
		dd = "0" + dd;

// Format date and time to string to construct posix time object
	date_time = yyyy + mm + dd + "T" + time;
}


CGpsData::~CGpsData() {
  
 
// TODO Auto-generated destructor stub
}


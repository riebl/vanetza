#include <iostream>
#include <fstream>
using namespace std;

#include "CGpsData.hpp"

CGpsData::CGpsData() {
	// TODO Auto-generated constructor stub

}


// Function to read GPS data from file, populate LPV object and update router
void CGpsData::readFakeGPSData(vanetza::geonet::Router &routerObj) {
	// variable to store ifstream obj of GPS data file
	ifstream gpsFakeDataFile;

	// string variables created to store temporary data for processing
	string input_line, date, time, date_time, str_lat, str_long, heading, speed,
			str_N_S, str_E_W, timeFromNMEA;

	// double variables which will be passed to updateLPV function
	double headingFromNMEA, speedFromNMEA, latitudeFROMNMEA, longitudeFROMNMEA;

	// variable to keep count of number of lines in the file
	unsigned int line_number = 1;

	//to keep count of number of delimiter and fields in a line
	unsigned int delimCount, fieldCount;

	// initialized to false
	lpv_.position_accuracy_indicator = false;

	//variables needed for conversion of timestamp to milliseconds
	double conv_time, hrs, mins, seconds, milliSeconds;

	//vectors to store the timestamp in milliseconds and the time difference
	vector<double> timeStampVector;
	vector<double> timeDiffVector;
	vector<double>::iterator it;


	// Open the file containing fake GPS NMEA sentences
	gpsFakeDataFile.open(filePathFromTerminal);

	if ((gpsFakeDataFile.is_open()) && (!gpsFakeDataFile.eof())) {

		while (getline(gpsFakeDataFile, input_line)) {
			line_number++;
			delimCount = 0;

			//stream for splitting
			istringstream streamOfLine(input_line);

			//to count the number of delimiters in a line
			for (unsigned int i = 0; i < input_line.size(); i++) {
				if (input_line[i] == ',')
					delimCount++;
			}

			//Creates stringstream of fields
			stringstream fieldStream[++delimCount];
			fieldCount = 0;

			// To seperate the line using the seperator
			while (getline(streamOfLine, input_line, ',')) {

				fieldStream[fieldCount] << input_line;
				fieldCount++;

			}
			//condition to extract only GPRMC data
			if (fieldStream[0].str() == "$GPRMC") {
				//Condition to check if the line contains valid number of fields(NMEA RMC format has 13 fields)
				if (fieldCount == FIELD_COUNT) {
					// Extract timestamp from NMEA RMC sentence
					timeFromNMEA = fieldStream[1].str();

					//Conversion of timestamp into milliseconds
					hrs = stod(timeFromNMEA.substr(0, 2));
					mins = stod(timeFromNMEA.substr(2, 2));
					seconds = stod(timeFromNMEA.substr(4, 2));
					milliSeconds = stod(timeFromNMEA.substr(6, 4));
					conv_time = (hrs * 60 * 60 + mins * 60 + seconds)*1000
							+ milliSeconds*1000;

					// Add timestamp in milliSeconds to vector
					timeStampVector.push_back(conv_time);

				} else
					cout << "ERROR - No. of fields in the line " << line_number
							<< " is " << fieldCount << " expected fields: "
							<< FIELD_COUNT << endl;
			}
		}

	// Computes difference between the timestamps of
	for (it = timeStampVector.begin(); it != timeStampVector.end(); ++it) {
		//cout << "Timestamp of next NMEA  RMC data - Timestamp of present NMEA RMC data = " << *(it+1) - *it << "ms " << endl;
	  //cout << " Timestamp vector : "<< *it << endl;
		timeDiffVector.push_back(*(it + 1) - *it);
	}
	
	// Reset to start of file
	gpsFakeDataFile.clear();
	gpsFakeDataFile.seekg(0, ios::beg);
	line_number = 1;

	//it = timeDiffVector.begin();
	
		while (getline(gpsFakeDataFile, input_line)) {
			delimCount = 0;

			line_number++;

			//stream for splitting
			istringstream streamOfLine(input_line);

			//To count number of delimiters in the line
			for (unsigned int i = 0; i < input_line.size(); i++) {
				if (input_line[i] == ',')
					delimCount++;
			}

			//Creates stringstream of fields
			stringstream fieldStream[++delimCount];
			fieldCount = 0;

			// To seperate the line using the seperator
			while (getline(streamOfLine, input_line, ',')) {
				fieldStream[fieldCount] << input_line;
				fieldCount++;

			}
			//Extracts only GPRMC data
			if (fieldStream[0].str() == "$GPRMC") {
				//Condition to check if the line contains valid number of fields(NMEA RMC format has 13 fields)
				if (fieldCount == FIELD_COUNT) {

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

					// Extract heading from NMEA RMC sentence
					heading = fieldStream[10].str();
					if (heading.length() == 0)
						heading = "0";
					//Convert to double
					headingFromNMEA = stod(heading.c_str());

					// Extract speed from NMEA RMC sentence
					speed = fieldStream[8].str();
					speedFromNMEA = stod(speed.c_str());

					// format date and time read from NMEA RMC sentence to construct a posix_time object
					convertDateAndTime(date, time, date_time);

					// instantiate posix time object
					boost::posix_time::ptime ptimeObj;
					ptimeObj = boost::posix_time::from_iso_string(date_time);

					//Construct Timestamp object using posix time object
					vanetza::geonet::Timestamp timestampObj(ptimeObj);

					// update the member variables of long position vector
					updateLPV(latitudeFROMNMEA, longitudeFROMNMEA, timestampObj,
							headingFromNMEA, speedFromNMEA);

					
					cout << "Updated router with latitude:" << latitudeFROMNMEA << ", longitude:" << longitudeFROMNMEA 
					<< ", heading:" << headingFromNMEA << ", speed:" << speed << endl;
					
					
					
					// Function call to route::update()
					routerObj.update(lpv_);
				} else
					cout << "ERROR - No. of fields in the line " << line_number
							<< " is " << fieldCount << " expected fields: "
							<< FIELD_COUNT << endl;
			}
		}

		//set position_accuracy_indicator as false when no more data is there to be read or GPS reciever connection is down.
		lpv_.position_accuracy_indicator = false;

		//close the file containing fake data
		gpsFakeDataFile.close();
 	}

	else
		cout << "failed to open" << endl;
}

/**
 * Function to set delimiter for the current line
 * @param lineFromFile - current line read from the file
 * @param c			   - character to hold delimiter
 */

void CGpsData::updateLPV(double latitude, double longitude,
		vanetza::geonet::Timestamp timestampObj, double headingFromNMEA,
		double speedFromNMEA) {

	/*
	 *	please note the change in function parameters.
	 * 	lat and long no longer passed as reference. pos is passed as reference
	 */
	convertAngleValues(latitude, longitude, pos);

	// static cast to convert to type geo_angle_i32t
	lpv_.latitude = static_cast<vanetza::geonet::geo_angle_i32t>(pos.latitude);
	lpv_.longitude =
			static_cast<vanetza::geonet::geo_angle_i32t>(pos.longitude);

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
	lpv_.speed =
			static_cast<vanetza::geonet::LongPositionVector::speed_u15t>(m_speed);

}

void CGpsData::convertAngleValues(double latitude, double longitude,
		vanetza::geonet::GeodeticPosition& position) {
	double deg, mins, sec;
	double integral = 100.00;

	// Extracting and formatting time data
	mins = modf(latitude, &integral);
	deg = int(latitude);
	double deg1 = deg / 100;
	deg = int(deg1);
	double difference = (deg1 - deg) * 100;
	mins = mins + difference;
	longitude = deg + (mins / 60);
	integral = 1000.00;
	mins = modf(longitude, &integral);
	deg = int(longitude);
	deg1 = deg / 100;
	deg = int(deg1);
	difference = (deg1 - deg) * 100;
	mins = mins + difference;
	longitude = deg + (mins / 60);

	//latitude converted to degrees
	m_latitude = latitude * vanetza::units::degree;
	//latitude in degrees assgined to variable of geodetic position object
	position.latitude = m_latitude;

	//longitude converted to degrees
	m_longitude = longitude * vanetza::units::degree;
	//latitude in degrees assgined to variable of geodetic position object
	position.longitude = m_longitude;
}

/*
 *	 Function to format date and time read from NMEA RMC format to construct a posix_time object
 */
void convertDateAndTime(string date, string time, string &date_time) {
	// Temporary variables to process date and time
	string dd, mm, yyyy, hh, mins, ss;
	int intDate, intMonths, intYear, intMonthAndYear, intHour;
	double minutes, seconds, minsAndSeconds, timeValue;

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


 std::string CGpsData::filePathFromTerminal = "";


CGpsData::~CGpsData() {
// TODO Auto-generated destructor stub
}


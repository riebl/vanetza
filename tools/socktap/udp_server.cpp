#include "udp_server.hpp"
#include <vanetza/btp/ports.hpp>
#include <vanetza/asn1/cam.hpp>
#include <vanetza/asn1/denm.hpp>
#include <vanetza/asn1/packet_visitor.hpp>
#include <vanetza/facilities/cam_functions.hpp>
#include <boost/units/cmath.hpp>
#include <boost/units/systems/si/prefixes.hpp>
#include <chrono>
#include <exception>
#include <functional>
#include <iostream>
#include <thread>
#include <boost/asio/io_service.hpp>
#include <boost/asio.hpp>


// This is a very simple CA application sending CAMs at a fixed rate.




UDPServer::UDPServer(int port):
    port_(9001)
{
    this->server_port = port_;
    this->initializeSocket();
}

void UDPServer::initializeSocket(){
    if ( (this->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 

    memset(&this->server_addr, 0, sizeof(this->server_addr)); 

    this->server_addr.sin_family    = AF_INET; // IPv4 
    this->server_addr.sin_addr.s_addr = INADDR_ANY; 
    this->server_addr.sin_port = htons(this->server_port); 
      
    // Bind the socket with the server address 
    if ( bind(this->sockfd, (const struct sockaddr *)&this->server_addr,  
            sizeof(this->server_addr)) < 0 ) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
}

void UDPServer::handleReceivedUDP(){
    while (true)
    {
        socklen_t len;
        int n; 
        char buffer[1024];
        
        len = sizeof(this->client_addr);  //len is value/result 
    
        n = recvfrom(this->sockfd, (char *)buffer, 1024,  
                    MSG_WAITALL, ( struct sockaddr *) &this->client_addr, 
                    &len); 
        buffer[n] = '\0'; 
        printf("Client : %s\n", buffer); 
    }
    
}
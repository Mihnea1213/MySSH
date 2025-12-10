#ifndef MYSSH_COMMON_UTILS_H
#define MYSSH_COMMON_UTILS_H

#include <string>
#include "protocol.h" //Avem nevoie de MessageType

//Functia care impacheteaza datele si le trimite
bool send_packet(int sock, MessageType type, const std::string& data);

//Functie care citeste un pachet (Header+Date)
bool receive_packet(int sock, MessageType& type, std::string& data);

#endif
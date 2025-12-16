#ifndef MYSSH_COMMON_UTILS_H
#define MYSSH_COMMON_UTILS_H

#include <string>
#include <openssl/ssl.h>//Avem nevoide de structura SSL
#include "protocol.h" //Avem nevoie de MessageType

//Functia care impacheteaza datele si le trimite
//bool send_packet(int sock, MessageType type, const std::string& data);
//Acum primim un pointer SSL* in loc de int sock
//Aceasta functie cripteaza datele si le trimite
bool send_packet(SSL* ssl, MessageType type, const std::string& data);

//Functie care citeste un pachet (Header+Date)
//bool receive_packet(int sock, MessageType& type, std::string& data);
//Acum primim un pointer SSL* in loc de int sock
//Aceasta functie citeste date criptate si le decripteaza intern
bool receive_packet(SSL* ssl, MessageType& type, std::string& data);
#endif
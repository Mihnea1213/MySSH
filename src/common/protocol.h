#ifndef MYSSH_COMMON_PROTOCOL_H
#define MYSSH_COMMON_PROTOCOL_H

#include <cstdint> //Pentru uint32_t, uint8_t

//INTRERUPERE PRINCIPALA A CRIPTARII (daca se comenteaza aceasta linie, criptarea o sa fie dezactivata)
//#define USE_SSL

//Tipurile de mesaje posibile
enum class MessageType: uint8_t {
    CMD_EXEC = 1, //Client -> Server: "ls -la"
    CMD_OUTPUT = 2, //Server -> Client : "file1.txt file2.txt"
    CMD_ERROR = 3, //Server -> Client: "Command not found"
    AUTH_REQ = 4, //Client -> Server: User/Parola
    AUTH_RESP = 5, //Server -> CLient: Ok/Fail
    DISCONNECT = 6 //"Inchid conexiunea"
};

//Header-ul fix (Plic...TLV <Type-Length-Value>)
//Acesta va fi lipit la inceputul fiecarui mesaj
//Are dimensiune fixa: 4 bytes(length) + 1 byte(type) = 5 bytes
#pragma pack(push,1)
struct PacketHeader
{
   uint32_t length; //Cati bytes urmeaza
   MessageType type; //Ce fel de mesaj este
}__attribute__((packed)); //Fara spatii goale intre variabile
#pragma pack(pop)

#endif

#include "utils.h"
#include <iostream>
#include <vector>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h> //Pentru htonl, ntohl

//Send (Trimit mesaj complet:Header+Date)
bool send_packet(int sock, MessageType type, const std::string& data)
{
    //Pregatim header-ul
    PacketHeader header;
    header.type = type;
    header.length = data.size();

    //Convertim lungimea pentru retea (Host to Network Long)
    uint32_t net_len = htonl(header.length);

    //Trimitem header-ul (Type +Length)
    //Trimitem intai lungimea (4 bytes)
    if(write(sock, &net_len, sizeof(net_len)) != sizeof(net_len))
    {
        return false;
    }

    //Trimitem Tipul (1 byte)
    if(write(sock, &header.type, sizeof(header.type)) != sizeof(header.type))
    {
        return false;
    }

    //Trimitem Datele - Payload-ul (daca exista)
    if (header.length > 0)
    {
        if (write(sock, data.c_str(), header.length) != (ssize_t)header.length)
        {
            return false;
        }
    }

    return true;
}

//Receive
//Returneaza false daca conexiunea s-a inchis sau e eroare
bool receive_packet(int sock, MessageType& type, std::string& data)
{
    PacketHeader header;
    uint32_t net_len;

    //Citim Lungimea (4 bytes)
    if (read(sock, &net_len, sizeof(net_len)) <= 0) 
    {
        return false;
    }

    header.length = ntohl(net_len); //COnvertim inapoi (Network to Host Long)

    //Citim Tipul (1 byte)
    if(read(sock, &header.type, sizeof(header.type)) <= 0)
    {
        return false;
    }

    type = header.type; //Salvam tipul pentru apelant

    //Citim Datele (Payload-ul)
    data.clear();
    if (header.length > 0)
    {
        //Alocam un buffer temporar
        std::vector<char> buffer(header.length);
        ssize_t total_received = 0;

        //BUcla pentru a fi sigur ca primi toti bytes
        while (total_received < header.length)
        {
            int bytes = read(sock, buffer.data() + total_received, header.length - total_received);
            if(bytes <= 0)
            {
                return false;
            }
            total_received += bytes;
        }
        data.assign(buffer.data() , header.length);
    }
    return true;
}
#include "utils.h"
#include <iostream>
#include <vector>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h> //Pentru htonl, ntohl

//Send (Trimit mesaj complet:Header+Date)
//bool send_packet(int sock, MessageType type, const std::string& data)
//Acum trimitem mesajul criptat
bool send_packet(SSL* ssl, MessageType type, const std::string& data)
{
    //Pregatim header-ul
    PacketHeader header;
    header.type = type;
    header.length = data.size();

    //Convertim lungimea pentru retea (Host to Network Long)
    uint32_t net_len = htonl(header.length);

    //Trimitem header-ul (Type +Length)
    //Trimitem intai lungimea (4 bytes)
    /*if(write(sock, &net_len, sizeof(net_len)) != sizeof(net_len))
    {
        return false;
    }
    */
    //Acum trimitem totul criptat: SSL_write returneaza >0 daca a scris cu succes
    if (SSL_write(ssl,&net_len,sizeof(net_len)) <=0)
    {
        return false; //Eroare la scriere sau conexiune cazuta
    }

    //Trimitem Tipul (1 byte)
    /*if(write(sock, &header.type, sizeof(header.type)) != sizeof(header.type))
    {
        return false;
    }
    */
    //Trimitem criptat:
    if (SSL_write(ssl, &header.type, sizeof(header.type)) <= 0)
    {
        return false;
    }

    //Trimitem Datele - Payload-ul (daca exista)
    /*if (header.length > 0)
    {
        if (write(sock, data.c_str(), header.length) != (ssize_t)header.length)
        {
            return false;
        }
    }
    */
    //Timitem acum criptat
    if (header.length > 0)
    {
        if (SSL_write(ssl, data.c_str(), header.length) <= 0)
        {
            return false;
        }
    }

    return true;
}

//Receive
//Returneaza false daca conexiunea s-a inchis sau e eroare
//bool receive_packet(int sock, MessageType& type, std::string& data)
//Acum criptat
bool receive_packet(SSL* ssl, MessageType& type, std::string& data)
{
    PacketHeader header;
    uint32_t net_len;

    //Citim Lungimea (4 bytes)
    /*if (read(sock, &net_len, sizeof(net_len)) <= 0) 
    {
        return false;
    }*/
   //SSL_read ia datele criptate de pe retea, le decripteaza in memorie si ni le pune in variabila net_len.
   int bytes = SSL_read(ssl, &net_len, sizeof(net_len));
   if (bytes <= 0)
   {
        return false; // <= 0 inseamna fie eroare, fie ca celalalt a inchis conexiunea
   }

    header.length = ntohl(net_len); //Convertim inapoi (Network to Host Long)

    //Citim Tipul (1 byte)
    /*if(read(sock, &header.type, sizeof(header.type)) <= 0)
    {
        return false;
    }*/
    //Folosindu-ne de SSL_read
    bytes= SSL_read(ssl, &header.type, sizeof(header.type));
    if(bytes <= 0)
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
            /*
            int bytes = read(sock, buffer.data() + total_received, header.length - total_received);
            if(bytes <= 0)
            {
                return false;
            }
            total_received += bytes;*/

            //Citim restul de date necesare
            int current_bytes = SSL_read(ssl, buffer.data() + total_received, header.length - total_received);

            if(current_bytes <= 0)
            {
                return false;
            }
            total_received+= current_bytes;
        }
        data.assign(buffer.data() , header.length);
    }
    return true;
}
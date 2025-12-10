//CLient MySSH
//Rolul acestui program:
//1. Initializeaza conexiunea TCP catre server.
//2. Preia comenzi de la tastatura utilizatorului.
//3. Le trimite la server.
//4. Asteapta raspunsul (output-ul comenzii) si il afiseaza pe ecran.

#include <iostream>
#include <sys/socket.h> //pentru socket si connect
#include <arpa/inet.h> //Pentru adrese si conversii (sockaddr_in, inet_pton)
#include <unistd.h> //Pentru read,write,close
#include <cstring> //Pentru manipularea memorie (memset, strlen)
#include <string> //Pentru clasa std::string
#include "../common/utils.h" //Pentru send_packet,receive_packet
#include "../common/protocol.h" //Pentru MessageType

//Portul
#define PORT 2728

//Adresa IP a serverului.
//127.0.0.1 inseamna "acest calculator"
#define SERVER_IP "127.0.0.1"

int main()
{
    int sock = 0;
    struct sockaddr_in serv_addr; //Structura care tine detaliile despre unde ne conectam

    //Buffer-ul in care vom stoca raspunsul primit de la server.
    char buffer[4096] = {0};

    //Creare Socket
    //AF_INET = Folosim IPv4
    //SOCK_STREAM = Folosim TCP
    //0 = Protocolul default pentru TCP
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        std::cout << "\n[Eroare] Nu s-a putut crea socket-ul client. \n";
        return -1;
    }

    //Curatam structura de memorie
    memset(&serv_addr, 0 , sizeof(serv_addr));

    serv_addr.sin_family = AF_INET; // Setam familia de adrese la IPv4

    //Setam portul. Functia htons este necesara.
    serv_addr.sin_port = htons(PORT);

    //Convertim adresa IP  din text in format binar.
    //ient_pton = "Internet Presentation to Network"
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0)
    {
        std::cout << "\n[Eroare] Adresa IP invalida sau nesuportat. \n";
        return -1;
    }

    //Functia conncet initiaza "Handshale-ul TCP" (SYN,SYN-ACK,ACK)
    if(connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        std::cout << "\n[Eroare] Conexiunea a esuat. Verificam daca serverul este pornit!\n";
        return -1;
    }

    std::cout << "---Conectat la MySSH Server! ---\n";
    std::cout << "Scrie comenzi shell (ex: ls, pwd, whoami). Scrie 'exit' pentru a iesi.\n";

    //Bucla de comunicare
    while(true)
    {
        std::string msg;

        //Afisez un prompt
        std::cout << "MySSH> ";

        //Citim toata linia de la tastatura.
        std::getline(std::cin, msg);

        //Verificam daca utilizatorul vrea sa iasa
        if(msg == "exit")
        {
            std::cout << "Deconectare...\n";
            break;
        }

        //Daca utilizatorul nu a scris nimic,nu trimitem pachet gol
        if(msg.empty()) 
        {
            continue;
        }

        //Trimitem comanda impachetata (Tipul CMD_EXEC)
        if(!send_packet(sock,MessageType::CMD_EXEC,msg))
        {
            std::cout << "[Eroare] Nu s-a putut trimite mesajul la server.\n";
            break;
        }

        //Asteptam raspunsul impachetat
        MessageType type;
        std::string response;

        if(!receive_packet(sock,type,response))
        {
            std::cout << "Serverul a inchis conexiunea." << std::endl;
            break;
        }

        //Verificam ce am primit
        if(type == MessageType::CMD_OUTPUT||type == MessageType::CMD_ERROR)
        {
            std::cout << response << std::endl;
        }
    }

    //Inchidem socket-ul
    close(sock);
    return 0;
}
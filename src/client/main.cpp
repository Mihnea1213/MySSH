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

        //Trimitem string-ul catre server: send(socket, pointer_la_date, lungime_date, flaguri)
        int bytes_sent = send(sock, msg.c_str(), msg.length(), 0);
        if (bytes_sent<0)
        {
            std::cout <<"[Eroare] Nu s-a putut trimite mesajul la server.\n";
            break;
        }

        //Curatare buffer
        memset(buffer,0,sizeof(buffer));

        //Receptie: read() o sa "opreasca" programul client pana cand serverul trimite ceva inapoi.
        int valread = read(sock,buffer,sizeof(buffer) - 1);

        if (valread > 0)
        {
            //S-a primit ceva si trebuie afisat.
            std::cout << buffer << std::endl;
        }
        else if(valread == 0)
        {
            //Daca read intoarce 0 , inseamna ca serverul a inchis conexiunea (FIN)
            std::cout << "Serverul a inchis conexiunea." << std::endl;
            break;
        }
        else
        {
            //Eroare daca primim -1.
            std::cout << "[Eroare] Eroare la citirea din socket.\n";
            break;
        }
    }

    //Inchidem socket-ul
    close(sock);
    return 0;
}
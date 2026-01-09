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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../common/utils.h" //Pentru send_packet,receive_packet
#include "../common/protocol.h" //Pentru MessageType
#include "../common/crypto.h" //Pentru criptare

//Portul
#define PORT 2728

//Adresa IP a serverului.
//127.0.0.1 inseamna "acest calculator"
#define SERVER_IP "192.168.163.105"

// --- CULORI PENTRU TERMINAL ---
const std::string RED     = "\033[31m";
const std::string GREEN   = "\033[32m";
const std::string YELLOW  = "\033[33m";
const std::string BLUE    = "\033[34m";
const std::string CYAN    = "\033[36m";
const std::string RESET   = "\033[0m";
const std::string BOLD    = "\033[1m";

void clear_screen()
{
    // Secventa ANSI care curata ecranul si muta cursorul sus-stanga
    std::cout << "\033[2J\033[1;1H";
}

int main()
{
    clear_screen();

    #ifdef USE_SSL
    //Initializam Libraria Criptografica
    Crypto::init();

    //Creare COntext SSL (Client Mode)
    //Contextul tine minte regulile generale de criptare (ex: TLS 1.3)
    SSL_CTX* ctx = Crypto::create_context(false);
    SSL* ssl = nullptr;
    #endif

    int sock = 0;
    struct sockaddr_in serv_addr; //Structura care tine detaliile despre unde ne conectam

    //Creare Socket
    //AF_INET = Folosim IPv4
    //SOCK_STREAM = Folosim TCP
    //0 = Protocolul default pentru TCP
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        std::cout << RED << "\n[Eroare] Nu s-a putut crea socket-ul client. \n" << RESET;
        return -1;
    }

    //Curatam structura de memorie
    //memset(&serv_addr, 0 , sizeof(serv_addr));

    serv_addr.sin_family = AF_INET; // Setam familia de adrese la IPv4

    //Setam portul. Functia htons este necesara.
    serv_addr.sin_port = htons(PORT);

    //Convertim adresa IP  din text in format binar.
    //ient_pton = "Internet Presentation to Network"
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0)
    {
        std::cout << RED << "\n[Eroare] Adresa IP invalida sau nesuportat. \n" << RESET;
        return -1;
    }

    std::cout << BLUE << "Conectare la " << SERVER_IP << "..." << RESET << "\n";

    //Functia conncet initiaza "Handshale-ul TCP" (SYN,SYN-ACK,ACK)
    if(connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        std::cout << RED <<"\n[Eroare] Conexiunea a esuat. Verificam daca serverul este pornit!\n" << RESET;
        return -1;
    }

    #ifdef USE_SSL
    //!!!Start Criptare (Handshake)
    //Cream o structura SSL specifica pentru aceasta conexiune
    ssl = SSL_new(ctx);

    //Legam structura SSL de socket-ul TCP existent
    SSL_set_fd(ssl, sock);

    //Initiem negocierea securizata cu serverul
    //Aici se verifica certificatele si se genereaza cheile de sesiune
    if (SSL_connect(ssl) <= 0)
    {
        std::cout << RED << "[Eroare Fatala] SSL Handshake Failed! (Criptarea a esuat)\n" << RESET;
        Crypto::log_ssl_error("SSL_connect");
        return -1;
    }
    std::cout << GREEN << "--- Conectat SECURIZAT " << YELLOW << "(TLS/AES)" << GREEN << " la MySSH Server! ---\n" << RESET;

    #else
    //!!!ZONA NECRIPTATA
    std::cout << RED << "--- Conectat NECRIPTAT (TCP Simplu) la MySSH Server! ---\n";
    std::cout << "[ATENTIE] Traficul poate fi interceptat!\n" << RESET;
    #endif

    //AUTENTIFICARE
    std::string username, password;

    std::cout << "\n" << BOLD << "Autentificare necesara:" << RESET << "\n";
    std::cout << "Username: ";
    std::getline(std::cin, username);

    std::cout << "Password: ";
    std::getline(std::cin, password);

    //COnstruim payload-ul: "username password"
    std::string auth_payload = username + " " + password;

    #ifdef USE_SSL
    if(!send_packet(ssl, MessageType::AUTH_REQ, auth_payload))
    {
        return -1;
    }
    #else
    if(!send_packet(sock, MessageType::AUTH_REQ, auth_payload))
    {
        return -1;
    }
    #endif

    //Asteptam raspunsul
    MessageType auth_type;
    std::string auth_response;

    #ifdef USE_SSL
    if(!receive_packet(ssl, auth_type, auth_response))
    {
        return -1;
    }
    #else
    if(!receive_packet(sock, auth_type, auth_response))
    {
        return -1;
    }
    #endif

    if(auth_type == MessageType::AUTH_RESP && auth_response == "OK")
    {
       clear_screen(); // Curatam ecranul
        std::cout << GREEN << "=== Autentificare REUSITA! ===" << RESET << "\n";
        std::cout << "Bun venit, " << CYAN << username << RESET << ".\n"; 
        std::cout << "Scrie comenzi shell (ex: " << YELLOW << "ls -la" << RESET << ", " << YELLOW << "pwd" << RESET << ").\n";
        std::cout << "Scrie '" << RED << "exit" << RESET << "' pentru a te deconecta.\n";
        std::cout << "-----------------------------------------------------\n";
    }
    else
    {
        std::cout << RED << "\n[Eroare] User sau parola gresita! Serverul a inchis conexiunea.\n" << RESET;

        //Curatenie
        #ifdef USE_SSL
        if(ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        #endif
        close(sock);
        return 0;
    }

    //Bucla de comunicare
    while(true)
    {
        std::string msg;

        //Afisez un prompt
        std::cout << "\n" << CYAN << "MySSH> " << RESET;

        //Citim toata linia de la tastatura.
        std::getline(std::cin, msg);

        //Verificam daca utilizatorul vrea sa iasa
        if(msg == "exit")
        {
            std::cout << YELLOW << "Se deconecteaza...\n" << RESET;
            break;
        }

        //Daca utilizatorul nu a scris nimic,nu trimitem pachet gol
        if(msg.empty()) 
        {
            continue;
        }

        #ifdef USE_SSL
        //Trimitem comanda impachetata (Tipul CMD_EXEC)
        //doar ca acum trimitem pointer-ul ssl in loc de 'sock'
        if(!send_packet(ssl,MessageType::CMD_EXEC,msg))
        {
            std::cout << RED << "[Eroare] Nu s-a putut trimite mesajul la server.\n" << RESET;
            break;
        }
        #else
        //Trimitem comanda impachetata (Tipul CMD_EXEC)
        if(!send_packet(sock,MessageType::CMD_EXEC,msg))
        {
            std::cout << RED << "[Eroare] Nu s-a putut trimite mesajul la server.\n" << RESET;
            break;
        }
        #endif

        //Asteptam raspunsul impachetat
        MessageType type;
        std::string response;

        #ifdef USE_SSL
        if(!receive_packet(ssl,type,response))
        #else
        if(!receive_packet(sock,type,response))
        #endif
        {
            std::cout << RED << "Serverul a inchis conexiunea." << RESET << std::endl;
            break;
        }

        //Verificam ce am primit
        if(type == MessageType::CMD_OUTPUT) {
            std::cout << response; // Output normal
        } 
        else if (type == MessageType::CMD_ERROR) {
            std::cout << RED << response << RESET; // Erorile cu rosu
        }
    }

    //Inchidem socket-ul
    close(sock);

    #ifdef USE_SSL
    //Inchidem canalul SSL (trimite alerta de close_notify)
    if(ssl)
    {
    SSL_shutdown(ssl);
    SSL_free(ssl); //Eliberam memoria SSL
    }

    if (ctx)
    {
    SSL_CTX_free(ctx); //Eliberam contextul general
    Crypto::cleanup(); //Eliberam libraria
    }
    #endif

    return 0;
}
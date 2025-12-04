//Serverul MySSH
//Arhitectura: TCP Iterativ cu Fork (Proces per Client)
//FUnctionalitate: executa comenzi shell folosind pipe/fork/exec

#include <iostream>
#include <unistd.h> //Pentru write, read, close, fork, pipe, dup2, exec
#include <sys/socket.h> //Pentru socket, bind, listen, accept
#include <netinet/in.h> //Pentru structura sockaddr_in
#include <arpa/inet.h> //Pentru inet_ntoa
#include <sys/wait.h> //Pentru waitpid
#include <cstring> //Pentru memset,strlen
#include <string> //Necesar pentru std::string

#define PORT 2728

//Gestionarea proceselor Zombie...Procesele copil raman in stadiul de proces "Zombie"
//pana cand parintele ii citeste statusul de iesire.Aceasta functie curata aceste procese automat.
void sigchld_handler(int s)
{
    (void)s; //Ignoram parametrul deoarece nu ne intereseaza ce semnal a fost.

    //waitpid(-1) = Asteapta ORICE copil.
    //WNOHANG = Nu o sa se blocheze daca nu e nici un copil "Zombie"
    //Loop-ul asigura ca curata toti copii "Zombie"
    while(waitpid(-1,NULL,WNOHANG) > 0);
}

//Primeste o comanda si returneaza output-ul ei.
std::string execute_command(const char* cmd)
{
    //Definim pipe ul
    //pipefd[0] = capat de citire utilizat de parinte (server)
    //pipefd[1] = capat de scriere utilizat de copil (comanda executata)
    int pipefd[2];

    //Cream pipe ul
    if(pipe(pipefd) == -1)
    {
        return "Eroare: Nu s-a putut crea pipe-ul intern.";
    }

    //Clonam procesul curent (serverul)
    pid_t pid = fork();

    if(pid == -1)
    {
        return "Eroare: Fork esuat la executia comenzii.";
    }

    if (pid == 0) //Suntem in procesul copil
    {
        //Inchidem capatul de citire
        //Copilul doar executa o comada si SCRIE. El nu citeste nimic
        close(pipefd[0]);

        //Redirectionarea: dup2(old, new) copiaza descriptorul "old" peste "new"
        //STDOUT_FILENO (1) este iesirea standard (ecranul).
        //STDERR_FILENO (2) este iesirea de erori.
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);

        //Putem inchide pipdefd[1] deoarece avem copii in (1) si (2)
        close(pipefd[1]);

        //Executia efectiva... execl inlocuieste complet codul procesului curent cu programul specificat
        //Folosesc "/bin/sh" cu flag-ul "-c" pentru a putea executa comenzi complexe
        // (ex: "la -la /tmp"). Shell-ul se va ocupa de spargerea argumentelor.
        execl("/bin/sh", "sh", "-c", cmd, (char *) NULL);

        //Gestionare Erori.
        //Daca se ajunge la aceasta comanda, inseamna ca execl a dat eroare.
        exit(127); //127 = COmmand not found
    }
    else //Suntem in procesul parinte
    {
        //Inchidem capatul de scriere.
        //Este necesar deoarece, daca nu o facem, o sa se astepte la nesfarsit "End of File".
        close(pipefd[1]);

        std::string result = "";
        char buffer[128];
        ssize_t count;

        //Citim din pipe pana se termina datele.
        //read() returneaza 0 cand capetele de scriere a fost inchis de copil (adica comanda s-a terminat)
        //read() blocheaza executia pana vin date, deci serverul asteapta aici comanda.
        while ((count = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0)
        {
            buffer[count] = '\0'; //Adaugam terminatorul de sir manual
            result += buffer;
        }

        //Curatenie
        close(pipefd[0]); //Inchid si capatul de citire.

        //Eliminam procesul Zombie
        //Chiar daca am terminat de citi, copilul ramane in starea "Zombie" pana 
        //cand parintele citeste codul de exit. waitpid face exact asta.
        waitpid(pid, nullptr, 0);

        return result;
    }
}

//Aceasta functie ruleaza in procesul COPIL creat in main()
void handle_client(int client_sock)
{
    
    char buffer[1024];
    std::cout << "[Child Process] Client conectat. Astept comenzi..."<< std::endl;

    while(true)
    {
        //Curatam bufferul de memorie
        memset(buffer,0,sizeof(buffer));

        //Citim de la retea (Socket)
        //read() blocheaza executia pana cand clientul trimite ceva
        int bytes_read = read(client_sock, buffer, sizeof(buffer) - 1);

        //Verificam daca clientul s-a deconectat
        //Daca read returneaza 0 (EOF) sau -1 (Eroare), iesim din bucla.
        if(bytes_read <= 0)
        {
            std::cout << "[Child Process] Clientul s-a deconectat." << std::endl;
            break;
        }

        //Procesez textul primit
        //Si eliminam caracterul '\n'
        if (bytes_read > 0 && buffer[bytes_read-1] == '\n')
        {
            buffer[bytes_read-1] ='\0';
        }

        std::string command(buffer);

        //Ignoram comenzile goale
        if (command.empty())
        {
            continue;
        }

        //Logam comanda (pentru debug)
        std::cout << "[Child Process] Execut:" << command << std::endl;
        
        std::string output;

        //Verificam daca comanda incepe cu "cd"
        //strncmp returneaza 0 daca sirurile sunt identice pe primii n bytes
        if (strncmp(command.c_str(), "cd" , 2) == 0)
        {
            //Extragem calea (ignoram primele 3 caractere: "cd ")
            std::string path;

            if (command.length() > 3)
            {
                path = command.substr(3); //Luam tot ce e dupa "cd"
            }
            else
            {
                path = getenv("HOME"); //Daca scrii doar "cd", te duce in Home
            }

            //Incercam sa schimbam directorul
            if(chdir(path.c_str()) == 0)
            {
                output = ""; //Succes, nu afisam nimic
            }
            else
            {
                output = "Eroare: Nu s-a putut schimba directorul (Path invalid?)\n";
            }
        }
        else
        {
            //Daca NU este cd, o executam cu execute_command
            output = execute_command(command.c_str());
        }

        //Verificam daca output-ul e gol
        //Trebuie sa intoarcem ceva in cazul in care comanda nu afiseaza nimic
        if (output.empty())
        {
            output = "\n";
        }

        //Trimitem rezultatul inapoi la client prin socket
        write(client_sock, output.c_str(), output.length());
    }
    //Inchidem socket-ul cand iesim din bucla
    close(client_sock);
}

int main()
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    //Creare socket (IPv4, TCP)
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("Eroare la socket");
        exit(EXIT_FAILURE);
    }

    //Optiuni Socket (Reuse Address)
    //Putem sa repornim serverul imediat, fara sa asteptam eliberarea portului de catre OS
    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
    {
        perror("Eroare la setsockopt");
        exit(EXIT_FAILURE);
    }

    //Configuram adresa si port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; //Asculta pe orice interfata de retea
    address.sin_port = htons(PORT); //Portul 2728

    //Bind(Legam socket-ul de port)
    if(bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0)
    {
        perror("Eroare la bind");
        exit(EXIT_FAILURE);
    }

    //Listen
    if(listen(server_fd, 5) < 0)
    {
        perror("Eroare la listen");
        exit(EXIT_FAILURE);
    }

    //COnfigurare Handler pentru Zombie Processes
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("Eroare la sigaction");
        exit(1);
    }

    std::cout << "[Server] Astept conexiuni pe portul " << PORT << "..." << std::endl;

    //Bucla Principala (Accept Loop)
    while (true)
    {
        //Blocat: Asteapta un client nou
        if((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0)
        {
            perror("Eroare la accept");
            continue;
        }

        std::cout << "[Server] Conexiune noua de la: " << inet_ntoa(address.sin_addr) << std::endl;

        //FORK (Crearea procesului pentru client)
        pid_t pid = fork();

        if (pid < 0)
        {
            perror("Eroare la fork");
        }
        else if (pid == 0)
        {
            //In procesul copil
            //Copilul nu are nevoie sa asculte dupa alti clienti
            close(server_fd);

            //Copilul se ocupa doar de acest client
            handle_client(new_socket);

            //Cand handle_client se termina, copilul moare
            exit(0);
        }
        else
        {
            //In procesul parinte
            //Parintele nu vorbeste cu clientul curent (o face copilul)
            //Asa ca inchide socket-ul clientului in procesul parinte
            close(new_socket);
            //Parintele se intoarce la inceputul buclei while sa astepte urmatorul client
        }
    }
    return 0;
}
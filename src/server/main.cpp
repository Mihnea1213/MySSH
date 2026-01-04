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
#include <vector> //Necesar pentru std::vector
#include <sstream> //Necesar pentru std::stringsteam 
#include <fcntl.h> //opne, O_CREAT,O_WRONLY, etc.
#include <glob.h> //Pnetru procesare *
#include <signal.h> //Pentru resetarea semnalelor
#include <sys/resource.h> //Pentru setrlimit (Resource Governance)
#include <fstream> //Pentru fisiere log (Audit)
#include <chrono> //Pentru timestamp
#include <iomanip> //Pentru formatare timp
#include <limits.h> //Pentru PATH_MAX
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../common/utils.h" //Pentru send_packet,receive_packet
#include "../common/protocol.h" //Pentru MessageType
#include "../common/crypto.h"

#define PORT 2728

//Variabila globala pentru calea absoluta a log-ului
std::string server_log_path;
SSL_CTX* ctx = nullptr; //Contextul SSL Global

//Modul auditare: Scrie actiunile intr-un fisier jurnal pe server
void log_audit(const std::string& ip, const std::string& action, const std::string& details)
{
    //DEschidem fisierul in mod append
    std::ofstream log_file(server_log_path, std::ios::app);

    if (log_file.is_open())
    {
        //Obtinem timpul curent
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);

        log_file << "[" << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S") << "] "
                 << "IP: " << ip << " | "
                 << "ACTION: " << action << " | "
                 << "CMD: " << details << "\n";

                 log_file.flush();
    }
}

//Modul Resource Governance: Previne atacurile de tip Fork Bomb sau consum excesiv de memorie
void setup_resource_limits()
{
    struct rlimit rl;
    //Limita = Numar maxim de procese copil
    //Setam la 4096
    rl.rlim_cur= 4096;
    rl.rlim_max= 4096;
    if(setrlimit(RLIMIT_NPROC, &rl) != 0)
    {
        //Nu dam exit, doar avertizam in consola serverului
        perror("[Warning] Failed to set NPROC limit");
    }
}

//Elimina spatiile de la inceput si final
std::string trim(const std::string& str)
{
    size_t first = str.find_first_not_of(" \t\n\r");
    if(std::string::npos == first)
    {
        return "";
    }
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, (last-first+1));
}

//FUnctie care transforma "*" in lista de fisiere
std::vector<std::string> expand_wildcards(const std::vector<std::string>& args)
{
    std::vector<std::string> expanded_args;
    for (const auto& arg : args)
    {
        //Daca argumentul contine * sau ?, il expandam
        if(arg.find('*') != std::string::npos || arg.find('?') != std::string::npos || arg.front() == '~')
        {
            glob_t glob_result;
            memset(&glob_result, 0 , sizeof(glob_result));
            //GLOB_NOCHECK: Daca nu gaseste nimic, lasa argumentul asa cum e
            //GLOB_TILDE: Expandeaza si ~ catre home directory
            int return_value = glob(arg.c_str(), GLOB_TILDE | GLOB_NOCHECK, NULL, &glob_result);

            if (return_value == 0)
            {
                for (size_t i = 0 ; i < glob_result.gl_pathc; i++)
                {
                    expanded_args.push_back(std::string(glob_result.gl_pathv[i]));
                }
            }
            else
            {
                expanded_args.push_back(arg);
            }
            globfree(&glob_result);
        }
        else
        {
            expanded_args.push_back(arg);
        }
    }
    return expanded_args;
}

//Functia care scoate ghilimelele de la inceput si final
std::string strip_quotes(const std::string& str)
{
    if (str.length() >= 2)
    {
        char first = str.front();
        char last = str.back();
        //Verificam ghilimele duble sau simple
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            return str.substr(1, str.length() - 2);
        }
    }
    return str;
}

//Spargem un string dupa un delimitator (ex: "cmd1 | cmd2" -> {"cmd1", "cmd2"})
std::vector<std::string> split_string(const std::string& str, const std::string& delimiter)
{
    std::vector<std::string> tokens;
    size_t prev = 0 , pos = 0;
    while ((pos = str.find(delimiter,prev)) != std::string::npos)
    {
        tokens.push_back(trim(str.substr(prev,pos-prev)));
        prev = pos + delimiter.length();
    }
    tokens.push_back(trim(str.substr(prev)));
    return tokens;
}

//Logica de executie: Structura pentru a procesa argumentele finale si redirectionarile
struct CommandInfo
{
    std::vector<std::string> args;
    std::string input_file; //pt <
    std::string output_file; //pt >
    std::string error_file; //pt 2>
    bool append_out = false; //pt >>
};

//Functia Finala : Executa o singura comanda binare...Aici tratam redirectionarile
int execute_single_binary(const std::string& cmd_str)
{
    //Parsing argumente si detectie redirectari
    std::stringstream ss(cmd_str);
    std::string segment;
    CommandInfo info;

    std::vector<std::string>temp_parts;
    while(ss >> segment)
    {
        temp_parts.push_back(segment);
    }

    for (size_t i = 0 ; i < temp_parts.size(); i++)
    {
        if(temp_parts[i] == "<" && i+1 < temp_parts.size())
        {
            info.input_file = strip_quotes(temp_parts[++i]);
        }
        else if (temp_parts[i] == ">" && i+1 < temp_parts.size())
        {
            info.output_file = strip_quotes(temp_parts[++i]);
            info.append_out = false;
        }
        else if (temp_parts[i] == ">>" && i+1 < temp_parts.size())
        {
            info.output_file = temp_parts[++i];
            info.append_out = true;
        }
        else if (temp_parts[i] == "2>" && i+1 < temp_parts.size())
        {
            info.error_file = strip_quotes(temp_parts[++i]);
        }
        else
        {
            info.args.push_back(strip_quotes(temp_parts[i]));
        }
    }

    if(info.args.empty())
    {
        return 0;
    }

    //Tratare "cd" (chiar daca e intr-un pipe, il incercam, dar efectul "cd" intr-un pipe
    //dispare cand procesul moare. Totusi, e necesar sa fie aici pt cazul fara pipe.)
    if (info.args[0] == "cd")
    {
        const char* path = (info.args.size() > 1) ? info.args[1].c_str() : getenv("HOME");
        if(chdir(path) != 0)
        {
            perror("cd failed");
            return 1;
        }
        return 0;
    }

    //Fork pentru executia efectiva
    pid_t pid = fork();
    if (pid == 0)
    {
        //Procesul copil
        //Aplicam redirectionarile
        if(!info.input_file.empty())
        {
            int fd = open(info.input_file.c_str(), O_RDONLY);
            if(fd < 0)
            {
                perror("Input redirect failed");
                exit(1);
            }
            dup2(fd,STDIN_FILENO);
            close(fd);
        }

        if(!info.output_file.empty())
        {
            int flags = O_WRONLY | O_CREAT | (info.append_out ? O_APPEND : O_TRUNC);
            int fd = open(info.output_file.c_str(), flags, 0644);
            if(fd < 0)
            {
                perror("Output redirect failed");
                exit(1);
            }
            dup2(fd,STDOUT_FILENO);
            close(fd);
        }

        if(!info.error_file.empty())
        {
            int fd = open(info.error_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if(fd < 0)
            {
                perror("Error redirect failed");
                exit(1);
            }
            dup2(fd, STDERR_FILENO);
            close(fd);
        }

        std::vector<std::string> expanded_args = expand_wildcards(info.args);

        //Convertim vector<string> in char* argv[]
        std::vector<char*> c_args;
        for(const auto& arg : expanded_args)
        {
            c_args.push_back(const_cast<char*>(arg.c_str()));
        }
        c_args.push_back(nullptr);

        //Executam
        execvp(c_args[0], c_args.data());

        //Daca ajungem aici,execvp a dat fail
        std::cerr << "MySSH: command not found: " << info.args[0] << "\n";
        exit(127);
    }
    else if(pid > 0)
    {
        //Parinte
        int status;
        waitpid(pid,&status,0);
        if(WIFEXITED(status))
        {
            return WEXITSTATUS(status);
        }
        return 1;
    }
    return -1; //Fork error
}

//Procesare Pipe-uri(|)
int execute_pipes(const std::string& cmd_str)
{
    //Spargem dupa "|"
    std::vector<std::string> commands = split_string(cmd_str, "|");
    if (commands.size() == 1)
    {
        return execute_single_binary(commands[0]);
    }

    //Avem pipe-uri
    int num_cmds = commands.size();
    int pipefd[2];
    int prev_fd = -1; //Output-ul comenzii anterioare

    //Trebuie sa tinem minte PID-urile copiilor pentru a le verifica statusul la final
    std::vector<pid_t> child_pids;

    for (int i = 0 ; i < num_cmds; i++)
    {
        if (i < num_cmds - 1)
        {
            pipe(pipefd); //Cream pipe intre curent si urmatorul
        }

        pid_t pid = fork();
        if(pid == 0)
        {
            //Copil
            //Intrare: Daca nu e primul, citim de la cel anterior
            if (prev_fd != -1)
            {
                dup2(prev_fd,STDIN_FILENO);
                close(prev_fd);
            }

            //Iesire: Daca nu e ultimul, scriem in pipe pt urmatorul
            if (i < num_cmds - 1)
            {
                close(pipefd[0]); //Nu citim
                dup2(pipefd[1],STDOUT_FILENO);
                close(pipefd[1]);
            }

            //Executam comanda (care poate avea redirectari >,<,2>)
            //Aici apelam execute_single_binary dar trebuie sa ne asiguram ca nu face
            //waitpid in copil,ci exec direct. Pentru simplificare, vom parsa manual aici
            //execvp-ul final ca sa evitam fork in fork inutil

            //Refolosim logica de parsing din execute_single_binary, dar cu exit direct
            int ret_code=execute_single_binary(commands[i]);
            exit(ret_code);//Iesim cu codul comenzii
        }
        else
        {
            //Parinte
            if(prev_fd != -1)
            {
                close(prev_fd);//Inchidem capatul vechi
            }

            if(i < num_cmds - 1)
            {
                prev_fd = pipefd[0]; //Salvam capatul de citire
                close(pipefd[1]); //Inchidem capatul de scriere
            }

            child_pids.push_back(pid);
        }
    }

    int last_exit_code = 0;
    for(size_t i = 0 ; i < child_pids.size(); i++)
    {
        int status;
        waitpid(child_pids[i], & status, 0);

        //Ne intereseaza doar statusul ultimei comenzi din pipe

        if (i == child_pids.size() - 1)
        {
            if(WIFEXITED(status))
            {
                last_exit_code = WEXITSTATUS(status);
            }
            else
            {
                last_exit_code = -1;
            }
        }
    }
    return last_exit_code;
}

//Procesare logic (&&,||)
int execute_logic(const std::string& cmd_str)
{
    //Aici vom cauta primul operator && sau || si vom sparge recursiv.
    size_t and_pos = cmd_str.find("&&");
    size_t or_pos = cmd_str.find("||");

    if(and_pos == std::string::npos && or_pos == std::string::npos)
    {
        return execute_pipes(cmd_str);
    }

    //Determinam care apare primul
    if(and_pos != std::string::npos && (or_pos == std::string::npos || and_pos < or_pos))
    {
        //Avem: CMD1 && RESTUL
        std::string cmd1 = trim(cmd_str.substr(0,and_pos));
        std::string rest = trim(cmd_str.substr(and_pos + 2));
        
        int status = execute_pipes(cmd1);
        if(status == 0)
        {
            return execute_logic(rest);
        }
        return status; //Returnam eroarea din stanga a esuat
    }
    else
    {
        //OPeratorul || apare primul
        //Avem CMD1 || RESTUL
        std::string cmd1 = trim(cmd_str.substr(0,or_pos));
        std::string rest = trim(cmd_str.substr(or_pos + 2));

        //Executam partea din stanga
        int status = execute_pipes(cmd1);

        //Executam dreapta doar daca stanga a esuat
        if(status != 0)
        {
            return execute_logic(rest);
        }
        return 0;//Daca stanga a mers,nu mai executam dreapta
    }
}

//Procesarea Secventiala (;)
void execute_full_command_structure(const std::string& raw_cmd)
{
    std::vector<std::string> commands = split_string(raw_cmd, ";");
    for (const auto& cmd: commands)
    {
        if(!cmd.empty())
        {
            execute_logic(cmd);
        }
    }
}

//Itegrarea cu serverul
//Captureaza tot output-ul generat de functiile de mai sus.
std::string execute_command(const char* cmd)
{
    int pipefd[2];
    if(pipe(pipefd) == -1)
    {
        return "Eroare: Pipe failed.";
    }

    pid_t pid = fork();

    if (pid == -1)
    {
        return "Eroare: Fork failed.";
    }

    if (pid == 0)
    {
        //Proces supervisor (temporar)
        //Acest proces exista doar pentru a executa comnzile si a le
        //trimite output-ul in pipe-ul principal.
        //De asemenea, resetam handlerul pentru SIGCHLD pentru a evita deadlocks
        //Activam si limitarea resurselor in procesul SUpervisor , iar copiii o sa mosteneasca limita
        setup_resource_limits();
        signal(SIGCHLD, SIG_DFL);
        close(pipefd[0]); //Inchidem citirea
        dup2(pipefd[1], STDOUT_FILENO);// Redirectionam stdout in pipe
        dup2(pipefd[1], STDERR_FILENO); // Redirectionam stderr in pipe
        close(pipefd[1]);

        execute_full_command_structure(cmd);
        exit(0); //Supervisorul moare dupa ce termina comenzile
    }
    else //Procesul Server (Parinte)
    {
        close(pipefd[1]);

        std::string full_output = "";
        char buffer[256];
        ssize_t bytes_read;

        while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0)
        {
            buffer[bytes_read] = '\0';
            full_output += buffer;
        }

        close(pipefd[0]);
        waitpid(pid, nullptr, 0);

        return full_output;
    }
}

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

//Verificare user/parola din fisier text (Flat_file storage)
bool check_credentials(const std::string& input_user, const std::string& input_pass)
{
    std::ifstream user_file("users.txt");
    if(!user_file.is_open())
    {
        std::cerr << "[Eroare] Nu am gasit fisierul users.txt!\n";
        return false;
    }

    std::string line_user, line_pass;
    while (user_file >> line_user >> line_pass)
    {
        if(line_user == input_user && line_pass == input_pass)
        {
            return true; //Am gasit potrivirea
        }
    }
    return false; //Nu am gasit
}

//Aceasta functie ruleaza in procesul COPIL creat in main()
#ifdef USE_SSL
void handle_client(SSL* ssl, std::string client_ip)
#else
void handle_client(int sock, std::string client_ip)
#endif
{
    MessageType type;
    std::string payload;
    std::cout << "[Child Process] Client conectat. Astept comenzi..."<< std::endl;

    //AUTENTIFICARE
    //Asteptam primul pachet sa fie neaparat AUTH_REQ
    std::cout << "[Auth] Astept credențialele de la " << client_ip << "...\n";
    
    #ifdef USE_SSL
    if(!receive_packet(ssl,type,payload))
    {
        return ;
    }
    #else
    if(!receive_packet(sock,type,payload))
    {
        return ;
    }
    #endif

    if (type != MessageType::AUTH_REQ)
    {
        std::cout << "[Auth] Eroare: Clientul nu a trimis cerere de autentificare.\n";
        return;
    }

    //Parsam payload-ul (Format: "user password")
    std::stringstream ss(payload);
    std::string user, pass;
    ss >> user >> pass;

    if(user.empty() || pass.empty())
    {
        std::cout << "[Auth] Eroare: Format invalid (lipseste user sau parola).\n";
        return;
    }

    //Verificam in baza de date (users.txt)
    bool auth_success = check_credentials(user,pass);

    if(auth_success)
    {
        std::cout << "[Auth] Succes! Utilizator conectat: " << user << "\n";
        log_audit(client_ip, "AUTH", "Login successful as " + user);
        #ifdef USE_SSL
        send_packet(ssl , MessageType::AUTH_RESP, "OK");
        #else
        send_packet(sock , MessageType::AUTH_RESP, "OK");
        #endif
    }
    else
    {
        std::cout << "[Auth] Eșec pentru " << client_ip << " (User: " << user << ")\n";
        log_audit(client_ip, "AUTH", "Login failed for " + user);
        #ifdef USE_SSL
        send_packet(ssl , MessageType::AUTH_RESP, "FAIL");
        #else
        send_packet(sock , MessageType::AUTH_RESP, "FAIL");
        #endif

        return; //DEconectam clientul imediat
    }

    std::cout << "[Child Process] Sesiune activa. Astept comenzi..."<< std::endl;

    while (true)
    {
        #ifdef USE_SSL
        if(!receive_packet(ssl,type,payload))
        #else
        //Folosim receive_packet 
        //Functia asta se ocupa de lungime si tip
        if(!receive_packet(sock,type,payload))
        #endif
        {
            std::cout << "[Child Process] Clientul s-a deconectat sau eroare protocol." << std::endl;
            log_audit(client_ip, "DISCONNECT", "Session ended");
            break;
        }

        //Verificam ce tip de mesaj am primit
        if(type == MessageType::CMD_EXEC)
        {
            std::string command = payload;

            //Ignoram comenzile goale
            if(command.empty())
            {
                continue;
            }

            std::cout << "[Child Process] Execut: " << command << std::endl;

            //Logam comanda primita inainte de executie
            log_audit(client_ip, "EXEC", command);

            std::string output;

            //Tratare speciala CD
            if(strncmp(command.c_str(),"cd",2)==0)
            {
                std::string path;
                if(command.length() > 3)
                {
                    path=command.substr(3);
                }
                else
                {
                    path = getenv("HOME");
                }

                path = strip_quotes(trim(path));

                if(chdir(path.c_str()) == 0)
                {
                    output= "";
                }
                else
                {
                    output = "Eroare: Nu s-a putut schimba directorul.\n";
                }
            }
            else
            {
                output = execute_command(command.c_str());
            }

            if(output.empty())
            {
                output="\n"; //Ca sa nu trimitem payload ul gol
            }

            #ifdef USE_SSL
            send_packet(ssl, MessageType::CMD_OUTPUT, output);
            #else
            //Trimitem raspunsul inapoi impachetat
            send_packet(sock, MessageType::CMD_OUTPUT, output);
            #endif
        }
    }
    #ifdef USE_SSL
    //Nu inchidem socketul aici, il inchide parintele sau SSL_shutdown
    //Copilul moare oricum
    #else
    //Inchidem socket-ul cand iesim din bucla
    close(sock);
    //Doar daca facem fara criptare
    #endif
}

int main()
{
    #ifdef USE_SSL
    //Initializare OpenSSl
    Crypto::init();

    //Creare COntext Server + Incarcare CHei
    ctx = Crypto::create_context(true);
    Crypto::configure_context(ctx, "../keys/server_cert.pem", "../keys/server_key.pem");
    std::cout << "[Info] Modul SECURIZE (SSL) Activat.\n";
    #else
    std::cout << "[Info] Modul NECRIPTAT (Standard TCP) Activat.\n";
    #endif

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    //Determinam directorul curent la pornire si salvam calea absoluta catrea log.
    char cwd[PATH_MAX];
    if(getcwd(cwd,sizeof(cwd)) != NULL)
    {
        server_log_path = std::string(cwd) + "/server_audit.log";
        std::cout << "[Audit] Logging to: " << server_log_path << std::endl;
    }
    else
    {
        server_log_path = "server_audit.log"; // Fallback
    }

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
        //Resetam addrlen la fiecare conexiune noua! Altfel, la a doua conexiune, accept primeste o dimensiune gresita si scrie gunoi in IP.
        addrlen = sizeof(address);
        //Blocat: Asteapta un client nou
        if((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0)
        {
            perror("Eroare la accept");
            continue;
        }

        //Obtinem IP-ul clientului ca string folosind inet_ntoa
        std::string ip_str = inet_ntoa(address.sin_addr);
        std::cout << "[Server] Conexiune noua de la: " << ip_str << std::endl;

        //Logam conexiunea noua
        log_audit(std::string(ip_str), "CONNECT", "New session established");

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

            #ifdef USE_SSL
            //!!!START SSL HANDSHAKE (In copil)
            SSL* ssl = SSL_new(ctx); //Cream o structura SSL
            SSL_set_fd(ssl, new_socket); // O legam de socket
            if(SSL_accept(ssl) <= 0) //Asteptam ca clientul sa inceapa negocierea
            {
                std::cerr << "[Eroare] SSL Handshake esuat cu " <<ip_str << "\n";
                Crypto::log_ssl_error("SSL_accept");
            }
            else
            {
                //Daca negocierea reuseste, intram in bucla de comenzi
                handle_client(ssl, ip_str);
            }
            //Copilul se ocupa doar de acest client
            
            //Curatenie Copil
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(new_socket);
            #else
            handle_client(new_socket, std::string(ip_str)); //asta daca lucram fara criptare
            #endif
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

    //Curatenie Parinte (teoretic unreachable code in while (true))
    #ifdef USE_SSL
    SSL_CTX_free(ctx);
    Crypto::cleanup();
    #endif
    return 0;
}
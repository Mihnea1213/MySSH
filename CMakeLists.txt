#Versiune minima de CMake...deoarece daca cineva are o versiune mai veche (ex: din 2015), s-ar putea sa nu inteleaga comenzile.
#3.10 este un standard safe
cmake_minimum_required(VERSION 3.10)
project(MySSH) #Numele Proiectului


#Standartul C++...Ii spunem compilatorului (g++) sa foloseasca regulile din 2017 (C++17)
#Facem asta ca sa nu primim erori la comenzi considerate "moderne"
set(CMAKE_CXX_STANDARD 17)

#Caut OpenSSL (folosit pentru metodele de criptare)
#"REQUIRED" se refera la faptul ca daca CMake nu gaseste OpenSSL instalat, da eroare
find_package(OpenSSL REQUIRED)

#Includerea Header-elor (.h)
#Folosit pentru organizarea mai buna a codului
include_directories(include src/common)

#!!!SERVERUL

#Crearea binarului Server
#Sintaxa: add_executable(NUME_BINAR  LISTA_FISIERE_SURSA)
#Aceasta comanda ia fisierele .cpp si le transforma in executabilul final "server".
add_executable(server
    src/server/main.cpp    
    src/common/utils.cpp
)

#Link-uiesc serverul cu bibliotecile necesare
#Deoarece folosesc OpenSSL, linker-ul trebuie sa "creeze conexiunea" dintre cod si biblioteci
#"pthread" este necesar pentru ca OpneSSL foloseste thread-uri in spate explicit si Linux cere asta explicit.
target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto pthread)

#!!!CLIENTUL

#La fel ca mai sus, creez un program separat "client"
add_executable(client
    src/client/main.cpp
    src/common/utils.cpp
)

#Link-uiesc clientul cu bibliotecile necesare
#Clientul are si el nevoie de metodele de criptare, deci explicatiile de mai de sus se aplica si aici
target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto pthread)
#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>

//Aceasta clasa este un wrapper peste OpenSSL.
class Crypto
{
public:
    //Initializarea librariei OpenSSL
    //Incarca algoritmi de criptare (AES,RSA,SHA,etc.) in memorie.
    static void init();

    //Curatare resurse
    // Se apeleaza la inchiderea programului pentru a elibera memoria OpenSSL.
    static void cleanup();

    //Creaza un context SSL (retea de criptare)
    //SSL_CTX e ca o "Fabrica de conexiuni"
    //Configuram reguli precum : "Suntem in server sau in client ?" , "Ce versiune de TLS folosim ?"
    //is_server = true -> incarca certificatele
    //is_server = false -> doar pregateste clientul
    static SSL_CTX* create_context(bool is_Server);

    //Configureaza Certificat-ul din folderul 'keys/' (Doar pentru Server)
    //Serverul trebuie sa incarce:
    //Certificatul Pubilc: Il arata clientului ca sa demonstreze cine e.
    //Cheia Privata: O tine secreta si o foloseste la decriptare.
    static void configure_context(SSL_CTX* ctx, const std::string& cert_file, const std::string& key_file);

    //Helper pentru afisarea erorilor OpenSSL
    static void log_ssl_error(const std::string& msg);
};

#endif
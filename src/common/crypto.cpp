#include "crypto.h"
#include <iostream>
#include <openssl/err.h>

void Crypto::init()
{
    //Incarca mesajele de eroare
    SSL_load_error_strings();

    //Incarca toti algoritmii criptografici (AES, RSA, SHA256, etc.)
    OpenSSL_add_all_algorithms();
}

void Crypto::cleanup()
{
    //CUrata memoria folosita de algoritmi
    EVP_cleanup();
}

void Crypto::log_ssl_error(const std::string& msg)
{
    std::cerr<< "[OpenSSL Error] " << msg << ": ";
    //ERR_print_errors_fp printeaza stiva de erori interne OpenSSL direct in stderr
    ERR_print_errors_fp(stderr);
    std::cerr<<std::endl;
}

SSL_CTX* Crypto::create_context(bool is_server)
{
    const SSL_METHOD* method;

    //Aici alegem "metoda" de comunicare
    //TLS_server_method() / TLS_client_method() sunt cele mai moderne
    //Ele negociaza automat cea mai buna versiune (TLS 1.2 sau 1.3)
    if (is_server)
    {
        method = TLS_server_method();
    }
    else
    {
        method = TLS_client_method();
    }

    //Cream contextul pe baza metodei alese
    SSL_CTX* ctx = SSL_CTX_new(method);
    if(!ctx)
    {
        log_ssl_error("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void Crypto::configure_context(SSL_CTX* ctx, const std::string& cert_file, const std::string& key_file)
{
    //Incarcam certificatul public (server_cert.pem)
    //Acesta va fi trimis clientilor cand se conecteaza.
    if(SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        log_ssl_error("Failed to load certificate: " + cert_file);
        exit(EXIT_FAILURE);
    }

    //Incarcam cheia privata (server_key.pem)
    //Aceasta ramane doar la noi (server)
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) <=0)
    {
        log_ssl_error("Failed to load private hey: " + key_file);
        exit(EXIT_FAILURE);
    }

    //Verificam daca Cheia Privata se potriveste cu Certificatul Public
    //Ca si cum verificam daca cheia intra in yala.
    if(!SSL_CTX_check_private_key(ctx))
    {
        log_ssl_error("Cheia privata nu corespunde cu certificatul public!");
        exit(EXIT_FAILURE);
    }
}
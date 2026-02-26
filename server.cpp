#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdint>

#define TOKEN "testUqac2026@"
#define BUFFER_SIZE 8192

using namespace std;

struct FileData {
    string filename;
    vector<unsigned char> enc_key;
    vector<unsigned char> iv;
    vector<unsigned char> cipher_data;
};

uint64_t ntohll(uint64_t val){
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return (((uint64_t)ntohl(val & 0xFFFFFFFF)) << 32) | ntohl(val >> 32);
#else
    return val;
#endif
}

uint64_t htonll(uint64_t val){
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return (((uint64_t)htonl(val & 0xFFFFFFFF)) << 32) | htonl(val >> 32);
#else
    return val;
#endif
}

int main() {
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD* method = DTLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if(!ctx){ cerr<<"Erreur SSL_CTX_new\n"; return 1; }

    if(SSL_CTX_use_certificate_file(ctx,"server_cert.pem",SSL_FILETYPE_PEM)<=0) return 1;
    if(SSL_CTX_use_PrivateKey_file(ctx,"server_key.pem",SSL_FILETYPE_PEM)<=0) return 1;

    int sock = socket(AF_INET, SOCK_DGRAM,0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4444);
    addr.sin_addr.s_addr = INADDR_ANY;

    if(bind(sock,(sockaddr*)&addr,sizeof(addr))<0){ cerr<<"Erreur bind\n"; return 1;}

    cout<<"Serveur DTLS en attente sur le port 4444...\n";

    unordered_map<string, FileData> files_storage;

    while(true){
        // Préparer BIO et SSL pour accepter un client
        BIO* bio = BIO_new_dgram(sock, BIO_NOCLOSE);
        SSL* ssl = SSL_new(ctx);
        SSL_set_bio(ssl,bio,bio);

        sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);

        cout<<"En attente de client...\n";
        if(DTLSv1_listen(ssl,(BIO_ADDR*)nullptr)<=0){
            SSL_free(ssl);
            continue;
        }

        cout<<"Client connecté via DTLS\n";

        // Réception token
        char buffer[BUFFER_SIZE];
        int n = SSL_read(ssl, buffer, BUFFER_SIZE);
        if(n<=0){ SSL_free(ssl); continue; }
        buffer[n]='\0';
        if(string(buffer)!=TOKEN){ cout<<"Token invalide\n"; SSL_free(ssl); continue; }

        // Réception commande
        n = SSL_read(ssl, buffer, BUFFER_SIZE);
        if(n<=0){ SSL_free(ssl); continue; }
        buffer[n]='\0';
        string cmd(buffer);

        if(cmd=="UPLOAD"){
            // Réception nom fichier
            n = SSL_read(ssl, buffer, BUFFER_SIZE);
            string filename(buffer,n);

            // Taille fichier
            uint64_t file_size_net;
            SSL_read(ssl,&file_size_net,sizeof(file_size_net));
            uint64_t file_size = ntohll(file_size_net);

            // Clé AES
            uint16_t enc_key_size_net;
            SSL_read(ssl,&enc_key_size_net,sizeof(enc_key_size_net));
            uint16_t enc_key_size = ntohs(enc_key_size_net);
            vector<unsigned char> enc_key(enc_key_size);
            SSL_read(ssl,enc_key.data(),enc_key.size());

            // IV
            vector<unsigned char> iv(16);
            SSL_read(ssl,iv.data(),16);

            // Fichier chiffré
            vector<unsigned char> cipher_data(file_size);
            size_t received=0;
            while(received<file_size){
                int to_read = BUFFER_SIZE;
                if(file_size-received<BUFFER_SIZE) to_read=file_size-received;
                int r = SSL_read(ssl, cipher_data.data()+received, to_read);
                if(r<=0) break;
                received += r;
            }

            files_storage[filename]={filename,enc_key,iv,cipher_data};
            cout<<"Fichier reçu et stocké : "<<filename<<" \n";

        } else if(cmd=="DOWNLOAD"){
            // Nom fichier demandé
            n = SSL_read(ssl, buffer, BUFFER_SIZE);
            string requested_file(buffer,n);

            if(files_storage.find(requested_file)==files_storage.end()){
                cout<<"Aucun fichier pour "<<requested_file<<"\n";
                SSL_free(ssl);
                continue;
            }

            FileData &f = files_storage[requested_file];

            uint16_t name_len = htons(f.filename.size());
            SSL_write(ssl,&name_len,sizeof(name_len));
            SSL_write(ssl,f.filename.c_str(),f.filename.size());

            uint64_t file_size_net = htonll(f.cipher_data.size());
            SSL_write(ssl,&file_size_net,sizeof(file_size_net));

            uint16_t enc_key_size = htons(f.enc_key.size());
            SSL_write(ssl,&enc_key_size,sizeof(enc_key_size));
            SSL_write(ssl,f.enc_key.data(),f.enc_key.size());

            SSL_write(ssl,f.iv.data(),f.iv.size());

            size_t sent=0;
            while(sent<f.cipher_data.size()){
                int to_send = BUFFER_SIZE;
                if(f.cipher_data.size()-sent<BUFFER_SIZE) to_send=f.cipher_data.size()-sent;
                SSL_write(ssl,f.cipher_data.data()+sent,to_send);
                sent+=to_send;
            }

            cout<<"Fichier envoyé au client : "<<f.filename<<" \n";
        }

        SSL_free(ssl);
    }

    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}

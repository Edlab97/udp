#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdint>

#define TOKEN "testUqac2026@"
#define BUFFER_SIZE 8192

using namespace std;

// Conversion 64 bits pour réseau
uint64_t htonll(uint64_t val){
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return (((uint64_t)htonl(val & 0xFFFFFFFF)) << 32) | htonl(val >> 32);
#else
    return val;
#endif
}

uint64_t ntohll(uint64_t val){
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return (((uint64_t)ntohl(val & 0xFFFFFFFF)) << 32) | ntohl(val >> 32);
#else
    return val;
#endif
}

// AES-256-CBC
bool aes_encrypt(const vector<unsigned char> &plaintext,
                 vector<unsigned char> &ciphertext,
                 vector<unsigned char> &key,
                 vector<unsigned char> &iv)
{
    key.resize(32);
    iv.resize(16);
    if(!RAND_bytes(key.data(), key.size())) return false;
    if(!RAND_bytes(iv.data(), iv.size())) return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return false;

    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data())){
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len;
    ciphertext.resize(plaintext.size() + 16);
    if(!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())){
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int ciphertext_len = len;
    if(!EVP_EncryptFinal_ex(ctx, ciphertext.data()+len, &len)){
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Chiffrement clé AES avec clé publique RSA
bool rsa_encrypt_key(const vector<unsigned char> &aes_key,
                     vector<unsigned char> &enc_key,
                     const string &pubkey_file)
{
    FILE *f = fopen(pubkey_file.c_str(),"r");
    if(!f) return false;
    EVP_PKEY *pubkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if(!pubkey) return false;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey,NULL);
    if(!ctx){ EVP_PKEY_free(pubkey); return false; }
    if(EVP_PKEY_encrypt_init(ctx)<=0){ EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pubkey); return false; }

    size_t outlen;
    if(EVP_PKEY_encrypt(ctx,NULL,&outlen,aes_key.data(),aes_key.size())<=0){
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pubkey); return false;
    }

    enc_key.resize(outlen);
    if(EVP_PKEY_encrypt(ctx,enc_key.data(),&outlen,aes_key.data(),aes_key.size())<=0){
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pubkey); return false;
    }
    enc_key.resize(outlen);
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pubkey);
    return true;
}

int main(int argc,char **argv){
    if(argc!=5){
        cout<<"Usage: "<<argv[0]<<" <IP> <PORT> <fichier_local> <clé_pub_dest>\n";
        return 1;
    }

    string server_ip = argv[1];
    int port = stoi(argv[2]);
    string filename = argv[3];
    string pubkey_file = argv[4];

    ifstream in(filename, ios::binary);
    if(!in){ cerr<<"Impossible d'ouvrir fichier\n"; return 1; }
    vector<unsigned char> buffer((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();

    vector<unsigned char> aes_key, iv, ciphertext;
    if(!aes_encrypt(buffer,ciphertext,aes_key,iv)){ cerr<<"Erreur AES\n"; return 1; }

    vector<unsigned char> enc_key;
    if(!rsa_encrypt_key(aes_key,enc_key,pubkey_file)){ cerr<<"Erreur RSA\n"; return 1; }

    // DTLS
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = DTLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if(!ctx){ cerr<<"Erreur SSL_CTX\n"; return 1; }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr);

    BIO *bio = BIO_new_dgram(sock,BIO_NOCLOSE);
    SSL *ssl = SSL_new(ctx);
    SSL_set_bio(ssl,bio,bio);
    if(SSL_connect(ssl)<=0){ cerr<<"Erreur DTLS connect\n"; return 1; }

    // Token
    SSL_write(ssl,TOKEN,strlen(TOKEN));

    // Commande UPLOAD
    string cmd="UPLOAD";
    SSL_write(ssl,cmd.c_str(),cmd.size());

    // Nom fichier
    SSL_write(ssl,filename.c_str(),filename.size());

    // Taille fichier
    uint64_t file_size_net = htonll(ciphertext.size());
    SSL_write(ssl,&file_size_net,sizeof(file_size_net));

    // Taille clé AES
    uint16_t enc_key_size = htons(enc_key.size());
    SSL_write(ssl,&enc_key_size,sizeof(enc_key_size));

    // Clé AES chiffrée
    SSL_write(ssl,enc_key.data(),enc_key.size());

    // IV
    SSL_write(ssl,iv.data(),iv.size());

    // Fichier chiffré
    size_t sent=0;
    while(sent<ciphertext.size()){
        int to_send = BUFFER_SIZE;
        if(ciphertext.size()-sent<BUFFER_SIZE) to_send=ciphertext.size()-sent;
        SSL_write(ssl,ciphertext.data()+sent,to_send);
        sent+=to_send;
    }

    cout<<"Fichier envoyé avec AES-256 \n";

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return 0;
}

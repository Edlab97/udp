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

// Conversion 64 bits réseau
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

// Déchiffrement AES-256-CBC
bool aes_decrypt(const vector<unsigned char> &ciphertext,
                 vector<unsigned char> &plaintext,
                 const vector<unsigned char> &key,
                 const vector<unsigned char> &iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return false;

    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data())){
        EVP_CIPHER_CTX_free(ctx); return false;
    }

    int len;
    plaintext.resize(ciphertext.size());
    if(!EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())){
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    int plaintext_len = len;
    if(!EVP_DecryptFinal_ex(ctx, plaintext.data()+len, &len)){
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Déchiffrement clé AES avec clé privée RSA
bool rsa_decrypt_key(const vector<unsigned char> &enc_key,
                     vector<unsigned char> &aes_key,
                     const string &privkey_file)
{
    FILE *f = fopen(privkey_file.c_str(),"r");
    if(!f) return false;
    EVP_PKEY *privkey = PEM_read_PrivateKey(f,NULL,NULL,NULL);
    fclose(f);
    if(!privkey) return false;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey,NULL);
    if(!ctx){ EVP_PKEY_free(privkey); return false; }
    if(EVP_PKEY_decrypt_init(ctx)<=0){ EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(privkey); return false; }

    size_t outlen;
    if(EVP_PKEY_decrypt(ctx,NULL,&outlen,enc_key.data(),enc_key.size())<=0){
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(privkey); return false;
    }

    aes_key.resize(outlen);
    if(EVP_PKEY_decrypt(ctx,aes_key.data(),&outlen,enc_key.data(),enc_key.size())<=0){
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(privkey); return false;
    }
    aes_key.resize(outlen);
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(privkey);
    return true;
}

int main(int argc,char **argv){
    if(argc!=4){
        cout<<"Usage: "<<argv[0]<<" <IP> <PORT> <nom_fichier>\n";
        return 1;
    }

    string server_ip = argv[1];
    int port = stoi(argv[2]);
    string filename = argv[3];

    //  OpenSSL DTLS
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
    if(SSL_connect(ssl)<=0){ cerr<<"Erreur DTLS \n"; return 1; }

    // Envoi token
    SSL_write(ssl,TOKEN,strlen(TOKEN));

    // Commande DOWNLOAD
    string cmd="DOWNLOAD";
    SSL_write(ssl,cmd.c_str(),cmd.size());

    // Nom du fichier à récupérer
    SSL_write(ssl,filename.c_str(),filename.size());

    // Lire nom fichier réel (taille + nom)
    uint16_t name_len_net;
    SSL_read(ssl,&name_len_net,sizeof(name_len_net));
    uint16_t name_len = ntohs(name_len_net);
    vector<char> name_buf(name_len);
    SSL_read(ssl,name_buf.data(),name_len);
    string recv_name(name_buf.begin(), name_buf.end());

    // Lire taille fichier
    uint64_t file_size_net;
    SSL_read(ssl,&file_size_net,sizeof(file_size_net));
    uint64_t file_size = ntohll(file_size_net);

    // Lire clé AES
    uint16_t enc_key_size_net;
    SSL_read(ssl,&enc_key_size_net,sizeof(enc_key_size_net));
    uint16_t enc_key_size = ntohs(enc_key_size_net);
    vector<unsigned char> enc_key(enc_key_size);
    SSL_read(ssl,enc_key.data(),enc_key_size);

    // Lire IV
    vector<unsigned char> iv(16);
    SSL_read(ssl,iv.data(),16);

    // Lire fichier chiffré
    vector<unsigned char> cipher(file_size);
    size_t received=0;
    while(received<file_size){
        int to_read = BUFFER_SIZE;
        if(file_size-received<BUFFER_SIZE) to_read=file_size-received;
        int r = SSL_read(ssl,cipher.data()+received,to_read);
        if(r<=0) break;
        received += r;
    }

    // Déchiffrement clé AES
    vector<unsigned char> aes_key;
    if(!rsa_decrypt_key(enc_key,aes_key,"clientB_private.pem")){
        cerr<<"Erreur déchiffrement clé AES\n"; return 1;
    }

    // Déchiffrement fichier
    vector<unsigned char> plaintext;
    if(!aes_decrypt(cipher,plaintext,aes_key,iv)){
        cerr<<"Erreur déchiffrement fichier\n"; return 1;
    }

    string out_path = "/home/vboxuser/Desktop/" + recv_name;
    ofstream out(out_path, ios::binary);
    if(!out){ cerr<<"Impossible de créer fichier\n"; return 1; }
    out.write((char*)plaintext.data(), plaintext.size());
    out.close();

    cout<<"Fichier reçu et déchiffré sur Desktop : "<<recv_name<<" \n";

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return 0;
}

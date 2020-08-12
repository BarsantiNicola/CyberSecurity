
#ifndef FOURINAROW_CIPHERRSA_H
#define FOURINAROW_CIPHERRSA_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>
#include <cstring>

using namespace std;
namespace cipher {
    class CipherRSA {
        private:
            EVP_PKEY* pubKey;
            EVP_PKEY* privKey;

        public:
            CipherRSA(string username, string password);
            CipherRSA(string username, string password, string mySqlUsername, string mySqlPassword );

    };
}

#endif //FOURINAROW_CIPHERRSA_H

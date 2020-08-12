
#include "CipherRSA.h"
#include "../Logger.h"

namespace cipher{

    CipherRSA::CipherRSA(string username, string password) {

        vverbose<<"--> [CipherRSA][Costructor] Searching user RSA keys"<<'\n';
        char* privKey = new char[8];
        strcpy( privKey, "data/");
        char* pubKey = new char[8];
        strcpy( pubKey, "data/");
        strcat( privKey , username.c_str()  );
        strcat( pubKey, username.c_str() );
        strcat( privKey , "PrivRSA.pem" );
        strcat( pubKey , "PubRSA.pem");
        FILE* publicKey = fopen( pubKey ,"r");
        FILE* privateKey = fopen( privKey , "r" );

        if( !publicKey || !privateKey ){

            verbose<<"--> [CipherRSA][Costructor] Error username undefined, keys not found"<<'\n';
            this->pubKey = nullptr;
            this->privKey = nullptr;

        }else{
            vverbose<<"--> [CipherRSA][Costructor] "<<username<<"'keys found"<<'\n';
            this->pubKey = PEM_read_PUBKEY( publicKey, nullptr, nullptr , nullptr);
            if( ! this->pubKey )
                verbose<<"--> [CipherRSA][Costructor] Unable to extract "<<username<<" public key"<<'\n';
            else
                vverbose<<"--> [CipherRSA][Costructor] "<<username<<" public key correctly loaded"<<'\n';
            this->privKey = PEM_read_PrivateKey( privateKey, nullptr, nullptr , (void*)password.c_str());
            if( ! this->privKey )
                verbose<<"--> [CipherRSA][Costructor] Unable to extract "<<username<<" private key"<<'\n';
            else
                vverbose<<"--> [CipherRSA][Costructor] "<<username<<" private key correctly loaded"<<'\n';

            delete[] publicKey;
            delete[] privateKey;

        }

        delete[] privKey;
        delete[] pubKey;
 
    }

}

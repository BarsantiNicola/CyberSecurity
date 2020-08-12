
#include "CipherRSA.h"
#include "../Logger.h"

namespace cipher{

    CipherRSA::CipherRSA(string username, string password) {

	
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
	cout<<"Searching files: "<<pubKey<<"  :  "<<privKey<<endl;
	cout<<"INFO: "<<publicKey<<"  :  "<<privateKey<<endl;
        if( !publicKey || !privateKey ){
            verbose<<"Error, username undefined"<<'\n';
            this->pubKey = nullptr;
            this->privKey = nullptr;
        }else{
            cout<<"Files founded"<<endl;
            this->pubKey = PEM_read_PUBKEY( publicKey, nullptr, nullptr , nullptr);
            cout<<"File founded"<<endl;
            this->privKey = PEM_read_PrivateKey( privateKey, nullptr, nullptr , (void*)password.c_str());
            cout<<"publicKey: "<<this->pubKey<<endl<<endl;
            cout<<"privateKey: " <<this->privKey<<endl;
        }
 
    }

}

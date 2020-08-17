
#include "CipherRSA.h"
#include "../Logger.h"

namespace cipher{

    CipherRSA::CipherRSA( string username, string password ) {

        vverbose<<"--> [CipherRSA][Costructor] Searching user RSA keys"<<'\n';

        FILE* caPublicKey = fopen( "data/caPubRSA.pem" , "r" );

        this->advKey = nullptr;

        if( !caPublicKey ){
            base<<"--> [CipherRSA][Costructor] Fatal Error, unable to locate caPubRSA.pem file"<<'\n';
            exit(1);
        }        cout<<"ok2"<<endl;
        vverbose<<"--> [CipherRSA][Costructor] CA key found"<<'\n';

        this->caKey = PEM_read_PUBKEY( caPublicKey, nullptr, nullptr , nullptr);

        fclose(caPublicKey);
        /*if( ! this->caKey ) {
            verbose << "--> [CipherRSA][Costructor] Fatal Error! Unable to extract CA'public key" << '\n';
            exit(1);
        }else
            vverbose<<"--> [CipherRSA][Costructor] CA'public key correctly loaded"<<'\n';
*/
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
            fclose(publicKey);

            this->privKey = PEM_read_PrivateKey( privateKey, nullptr, nullptr , (void*)password.c_str());
            if( ! this->privKey )
                verbose<<"--> [CipherRSA][Costructor] Unable to extract "<<username<<" private key"<<'\n';
            else
                vverbose<<"--> [CipherRSA][Costructor] "<<username<<" private key correctly loaded"<<'\n';
            fclose(privateKey);

        }

        delete[] privKey;
        delete[] pubKey;

    }

    CipherRSA::CipherRSA( string serverName, string password, string mySqlUsername, string mySqlPassword ){
        vverbose<<"--> [CipherRSA][Costructor] Searching user RSA keys"<<'\n';
        char* privKey = new char[17+serverName.length()];
        strcpy( privKey, "data/");
        char* pubKey = new char[16+serverName.length()];
        strcpy( pubKey, "data/");
        strcat( privKey , serverName.c_str()  );
        strcat( pubKey, serverName.c_str() );
        strcat( privKey , "PrivRSA.pem" );
        strcat( pubKey , "PubRSA.pem");
        FILE* publicKey = fopen( pubKey ,"r");
        FILE* privateKey = fopen( privKey , "r" );

        this->advKey = nullptr;
        this->caKey = nullptr;

        if( !publicKey || !privateKey ){

            verbose<<"--> [CipherRSA][Costructor] Error username undefined, keys not found"<<'\n';
            this->pubKey = nullptr;
            this->privKey = nullptr;

        }else{
            vverbose<<"--> [CipherRSA][Costructor] "<<serverName<<"'keys found"<<'\n';
            this->pubKey = PEM_read_PUBKEY( publicKey, nullptr, nullptr , nullptr);
            if( ! this->pubKey )
                verbose<<"--> [CipherRSA][Costructor] Unable to extract "<<serverName<<" public key"<<'\n';
            else
                vverbose<<"--> [CipherRSA][Costructor] "<<serverName<<" public key correctly loaded"<<'\n';
            this->privKey = PEM_read_PrivateKey( privateKey, nullptr, nullptr , (void*)password.c_str());
            if( ! this->privKey )
                verbose<<"--> [CipherRSA][Costructor] Unable to extract "<<serverName<<" private key"<<'\n';
            else
                vverbose<<"--> [CipherRSA][Costructor] "<<serverName<<" private key correctly loaded"<<'\n';

            fclose(publicKey);
            fclose(privateKey);


        }

        delete[] privKey;
        delete[] pubKey;

    }

    CipherRSA::~CipherRSA(){

        if( pubKey )
            EVP_PKEY_free( this->pubKey );

        if( privKey )
            EVP_PKEY_free( this->privKey );

        if( advKey )
            EVP_PKEY_free( this->advKey );

        if( caKey != nullptr )
            EVP_PKEY_free( this->caKey );


    }

    void CipherRSA::sign( Message* message ){

        unsigned char* compactForm = nullptr;//message->compactForm();
        if( compactForm != nullptr ) {
            int len = 0;
         //   int len = strlen((const char *) compactForm);
            unsigned char *signature = makeSignature(compactForm, len, this->privKey);
            cout<<len<<endl;
            message->setSignature(signature, len );
            delete[] compactForm;
        }


    }

    bool CipherRSA::clientVerifySignature( Message message , bool server ){
        unsigned char* signature = message.getSignature();
        unsigned char* compactMessage = nullptr;//message.compactForm();
        if( server )
            return verifySignature( compactMessage, signature , strlen((const char*)compactMessage), message.getSignatureLen(), this->pubKey );
        else
            return verifySignature( compactMessage, signature , strlen((const char*)compactMessage), message.getSignatureLen(), this->advKey );
    }

    bool CipherRSA::serverVerifySignature( Message message, string username ){

        vverbose<<"--> [CipherRSA][serverVerifySignature] Searching user RSA public key"<<'\n';

        char* pubKey = new char[15+username.length()+1];
        strcpy( pubKey, "data/");
        strcat( pubKey, username.c_str() );
        strcat( pubKey , "PubRSA.pem");
        FILE* publicKey = fopen( pubKey ,"r");

        EVP_PKEY* key;
        if( !publicKey){

            verbose<<"--> [CipherRSA][serverVerifySignature] Error username undefined, key not found"<<'\n';
            this->pubKey = nullptr;
            this->privKey = nullptr;

        }else{
            vverbose<<"--> [CipherRSA][Costructor] "<<username<<"'keys found"<<'\n';
            key = PEM_read_PUBKEY( publicKey, nullptr, nullptr , nullptr);
            if( ! this->pubKey )
                verbose<<"--> [CipherRSA][Costructor] Unable to extract "<<username<<" public key"<<'\n';
            else
                vverbose<<"--> [CipherRSA][Costructor] "<<username<<" public key correctly loaded"<<'\n';
            fclose(publicKey);

        }

        //delete[] pubKey;
        cout<<key<<endl;
        unsigned char* compactMessage = nullptr;//message.compactForm();
        unsigned char* signature = message.getSignature();
        return verifySignature( compactMessage, signature , strlen((const char*)compactMessage), message.getSignatureLen(), key );

    }

    bool CipherRSA::setAdversaryKey( EVP_PKEY* Key ){

        if( this->advKey != nullptr || Key == nullptr ) return false;

        this->advKey = Key;
        return true;

    }
    void CipherRSA::unsetAdversaryKey(){

        if( this->advKey != nullptr )
            EVP_PKEY_free( this->advKey );
        this->advKey = nullptr;

    }

    unsigned char* CipherRSA::makeSignature( unsigned char* fields, int& len, EVP_PKEY* privKey  ){

       unsigned char* signature;
       signature = (unsigned char*)malloc( EVP_PKEY_size(privKey));
       EVP_MD_CTX* ctx = EVP_MD_CTX_new();
       EVP_SignInit(ctx,EVP_sha256());
       EVP_SignUpdate( ctx, fields, (unsigned int)len);
       EVP_SignFinal(ctx,signature,(unsigned int*)&len,privKey);
       EVP_MD_CTX_free(ctx);
       return signature;
    }

    bool CipherRSA::verifySignature( unsigned char* msg, unsigned char* signature , int msgLen, int len, EVP_PKEY* pubKey ){

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_VerifyInit(ctx,EVP_sha256());
        EVP_VerifyUpdate(ctx,msg,msgLen );
        int ret = EVP_VerifyFinal(ctx,signature,len,pubKey);
        if( ret != 1 ){
            cout<<"Authentication error!!"<<endl;
            return false;
        }
        EVP_MD_CTX_free(ctx);
        return true;

    }

}

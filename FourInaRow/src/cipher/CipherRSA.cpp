
#include "CipherRSA.h"
#include "../Logger.h"

namespace cipher{

    CipherRSA::CipherRSA( string username, string password ) {

        vverbose<<"--> [CipherRSA][Costructor] Searching CA key"<<'\n';

        FILE* caPublicKey = fopen( "data/client_data/caPubRSA.pem" , "r" );

        this->advPubKey = nullptr;
        this->pubServerKey = nullptr;
        this->caKey = nullptr;

        if( !caPublicKey ){
            base<<"--> [CipherRSA][Costructor] Fatal Error, unable to locate caPubRSA.pem file"<<'\n';
            exit(1);
        }

        this->caKey = PEM_read_PUBKEY( caPublicKey, nullptr, nullptr , nullptr);
        fclose(caPublicKey);

        if( ! this->caKey ) {
            verbose << "--> [CipherRSA][Costructor] Fatal Error! Unable to extract CA'public key" << '\n';
            exit(1);
        }else
            vverbose<<"--> [CipherRSA][Costructor] CA'public key correctly loaded"<<'\n';
        vverbose<<"--> [CipherRSA][Costructor] CA key loaded"<<'\n';
        vverbose<<"--> [CipherRSA][Costructor] Searching "<<username<<"'RSA keys"<<'\n';

        string privKey = "data/client_data/";
        privKey.append(username).append( "PrivRSA.pem" );

        string pubKey = "data/client_data/";
        pubKey.append(username).append( "PubRSA.pem" );

        FILE* publicKey = fopen( pubKey.c_str() ,"r");
        FILE* privateKey = fopen( privKey.c_str() , "r" );

        if( !publicKey || !privateKey ){

            verbose<<"--> [CipherRSA][Costructor] Error username undefined, keys not found"<<'\n';
            this->myPrivKey = nullptr;
            this->myPubKey= nullptr;

        }else{
            vverbose<<"--> [CipherRSA][Costructor] "<<username<<"'keys found"<<'\n';

            this->myPubKey = PEM_read_PUBKEY( publicKey, nullptr, nullptr , nullptr);
            if( ! this->myPubKey )
                verbose<<"--> [CipherRSA][Costructor] Unable to extract "<<username<<" public key"<<'\n';
            else
                vverbose<<"--> [CipherRSA][Costructor] "<<username<<" public key correctly loaded"<<'\n';
            fclose(publicKey);

            this->myPrivKey = PEM_read_PrivateKey( privateKey, nullptr, nullptr , (void*)password.c_str());
            if( ! this->myPrivKey )
                verbose<<"--> [CipherRSA][Costructor] Unable to extract "<<username<<" private key"<<'\n';
            else
                vverbose<<"--> [CipherRSA][Costructor] "<<username<<" private key correctly loaded"<<'\n';
            fclose(privateKey);

        }

    }

    CipherRSA::CipherRSA( string serverName, string password, string users[] , int len ){

        vverbose<<"--> [CipherRSA][Costructor] Searching server RSA keys"<<'\n';

        string privKey = "data/server_data/";
        privKey.append(serverName).append( "PrivRSA.pem" );

        string pubKey = "data/server_data/";
        pubKey.append(serverName).append( "PubRSA.pem" );

        FILE* publicKey = fopen( pubKey.c_str() ,"r");
        FILE* privateKey = fopen( privKey.c_str() , "r" );

        this->advPubKey = nullptr;
        this->pubServerKey = nullptr;
        this->caKey = nullptr;

        if( !publicKey || !privateKey ){

            verbose<<"--> [CipherRSA][Costructor] Error, keys not found"<<'\n';
            this->myPrivKey = nullptr;
            this->myPubKey= nullptr;

        }else{

            vverbose<<"--> [CipherRSA][Costructor] server'keys found"<<'\n';

            this->myPubKey = PEM_read_PUBKEY( publicKey, nullptr, nullptr , nullptr);
            if( ! this->myPubKey )
                verbose<<"--> [CipherRSA][Costructor] Unable to extract server'public key"<<'\n';
            else
                vverbose<<"--> [CipherRSA][Costructor] server'public key correctly loaded"<<'\n';
            fclose(publicKey);

            this->myPrivKey = PEM_read_PrivateKey( privateKey, nullptr, nullptr , (void*)password.c_str());
            if( ! this->myPrivKey )
                verbose<<"--> [CipherRSA][Costructor] Unable to extract server'private key"<<'\n';
            else
                vverbose<<"--> [CipherRSA][Costructor] server'private key correctly loaded"<<'\n';
            fclose(privateKey);

        }

    }

    CipherRSA::~CipherRSA(){

        if( myPubKey )
            EVP_PKEY_free( this->myPubKey );

        if( myPrivKey )
            EVP_PKEY_free( this->myPrivKey );

        if( advPubKey )
            EVP_PKEY_free( this->advPubKey );

        if( caKey )
            EVP_PKEY_free( this->caKey );

        if( pubServerKey )
            EVP_PKEY_free( this->pubServerKey );



    }

    bool CipherRSA::sign( Message* message ){

        NetMessage* compactForm = Converter::compactForm( message->getMessageType() , *message );
        if( !compactForm ) {
            verbose << "-->[CipherRSA][sign] Error during the generation of the compact Form of the message" << '\n';
            return false;
        }

        unsigned int len = compactForm->length();
        unsigned char *signature = makeSignature( compactForm->getMessage() , len, this->myPrivKey );
        for( int a = 0; a<len;a++)
            cout<<(int)signature[a]<< ' ';
        cout<<endl;
        message->setSignature( signature, len );
        unsigned char *signature2 = message->getSignature();
        for( int a = 0; a<message->getSignatureLen();a++)
            cout<<(int)signature2[a]<< ' ';
        cout<<endl;
        delete compactForm;
        delete[] signature;
        return true;

    }


    bool CipherRSA::clientVerifySignature( Message message , bool server ){

        unsigned char* signature = message.getSignature();
        bool ret;
        if( !signature ){
            verbose<<"-->[CipherRSA][clientVerifySignature] Error, message hasn't a signature"<<'\n';
            return false;
        }

        NetMessage* compactMessage = Converter::compactForm(message.getMessageType() , message );
        if( compactMessage == nullptr || compactMessage->length() == 0 ){
            verbose<<"-->[CipherRSA][clientVerifySignature] Error during the generation of the compact message"<<'\n';
            delete[] signature;
            return false;
        }

        verbose<<"SIGNATURE:"<<'\n';
        for(int a = 0; a<message.getSignatureLen(); a++ )
            cout<<(int)signature[a]<< ' ';
        cout<<endl;
        if( server )
            ret = verifySignature( compactMessage->getMessage() , signature , compactMessage->length() , message.getSignatureLen(), this->myPubKey );
        else
            ret = verifySignature( compactMessage->getMessage() , signature , compactMessage->length() , message.getSignatureLen(), this->advPubKey );

        delete[] signature;
        delete compactMessage;
        return ret;

    }

    bool CipherRSA::serverVerifySignature( Message message, int socket ){

        return false;

    }

    bool CipherRSA::setAdversaryKey( EVP_PKEY* Key ){

        if( this->advPubKey ){
            verbose<<"-->[CipherRSA][setAdversaryKey] Error, adversary key already setted[USE unsetAdversaryKey before]"<<'\n';
            return false;
        }

        if( !Key ){
            verbose<<"-->[CipherRSA][setAdversaryKey] Error, null pointer passed as argument"<<'\n';
            return false;
        }

        this->advPubKey = Key;
        return true;

    }

    void CipherRSA::unsetAdversaryKey(){

        if( this->advPubKey != nullptr )
            EVP_PKEY_free( this->advPubKey );
        this->advPubKey = nullptr;

    }

    unsigned char* CipherRSA::makeSignature( unsigned char* compactMessage, unsigned int& len, EVP_PKEY* key  ){

        if( !compactMessage || !key || !len ){
            verbose<<"-->[CipherRSA][makeSignature] Error, invalid arguments"<<'\n';
            return nullptr;
        }

        verbose<<"COmpact Message"<<'\n';
        for( int a = 0; a<len; a++ )
            cout<<compactMessage[a];
        cout<<endl;
        unsigned int l = len;
        unsigned char* signature;
        signature = (unsigned char*)malloc( EVP_PKEY_size(key));
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_SignInit(ctx,EVP_sha256());
        EVP_SignUpdate( ctx, compactMessage, l);
        EVP_SignFinal(ctx,signature,(unsigned int*)&l,key);
        EVP_MD_CTX_free(ctx);
        len = l;
        verbose<<"signature created LEN: "<<len<<'\n';
        for( int a = 0; a<len;a++)
            cout<<(int)signature[a]<< ' ';
        cout<<endl;
        return signature;

    }

    bool CipherRSA::verifySignature( unsigned char* compactMessage , unsigned char* signature , int compactLen, int signatureLen, EVP_PKEY* key ){

        verbose<<"COmpact Message"<<'\n';
        for( int a = 0; a<compactLen; a++ )
            cout<<compactMessage[a];
        cout<<endl;
        verbose<<"signature verification LEN: "<<signatureLen<<'\n';
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_VerifyInit(ctx,EVP_sha256());
        EVP_VerifyUpdate(ctx,compactMessage, compactLen );
        if( EVP_VerifyFinal(ctx,signature,signatureLen,key) != 1 ){
            verbose<<"-->[CipherRSA][verifySignature] Authentication Error!"<<'\n';
            EVP_MD_CTX_free(ctx);
            return false;
        }
        verbose<<"-->[CipherRSA][verifySignature] Authentication Success!"<<'\n';
        EVP_MD_CTX_free(ctx);
        return true;

    }

    bool CipherRSA::test(){

        CipherRSA* rsa_1 = new CipherRSA( "bob" , "bobPassword");
        CipherRSA* rsa_2 = new CipherRSA( "alice" , "alicePassword");

        Message* message = new Message();
        message->setNonce(14);
        message->setMessageType( WITHDRAW_REQ );
        Message* message2 = new Message();
        message2->setNonce(9123124);
        message2->setMessageType( WITHDRAW_REQ );
        verbose<<"----------------------------------------------------"<<'\n';
        rsa_2->sign(message2);
        rsa_1->sign(message);

        verbose<<"----------------------------------------------------"<<'\n';

        rsa_1->setAdversaryKey(rsa_2->myPubKey);
        rsa_2->setAdversaryKey(rsa_1->myPubKey);
        rsa_1->clientVerifySignature(*message2, false );    //  USE THE ADVERSARY PUB KEY*/
        rsa_2->clientVerifySignature(*message,false );
        verbose<<"----------------------------------------------------"<<'\n';
     /*   NetMessage* net = Converter::encodeMessage(WITHDRAW_REQ, *message );
        unsigned char* signature= net->getMessage();
        for(int a = 0; a<net->length(); a++)
            cout << (int) signature[a] <<' ';
        cout<<endl;
        delete message;
        message = Converter::decodeMessage(*net);
        delete net;*/


        delete message;
        //delete message2;
        delete rsa_1;
      //  delete rsa_2;
        return true;

    }

}

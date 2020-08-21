
#include "CipherDH.h"

namespace cipher{


    CipherDH::CipherDH( string username, bool server ) {

        this->key = nullptr;
        FILE *dhParam;
        DH* parameter;
        if (server) {

            string dhKey = "data/server_data/";
            dhKey.append(username).append("DH.pem");

            dhParam = fopen(dhKey.c_str(), "r");

        } else {

            string dhKey = "data/client_data/";
            dhKey.append(username).append("DH.pem");

            dhParam = fopen(dhKey.c_str(), "r");
        }

        if (!dhParam)
            verbose << "--> [CipherDH][Costructor] Error " << username << " undefined, diffie-hellman parameters not found" << '\n';
        else{
            vverbose << "--> [CipherDH][Costructor] " << username << "'diffie-hellman parameters found" << '\n';

            parameter = PEM_read_DHparams( dhParam, nullptr, nullptr, nullptr );
            if (!parameter) {
                verbose << "--> [CipherDH][Costructor] Unable to extract " << username << " diffie-hellman parameters"<< '\n';
                fclose(dhParam);
                return;
            }else
                vverbose << "--> [CipherDH][Costructor] " << username << " diffie-hellman parameters correctly loaded" << '\n';
            fclose(dhParam);

        }

        this->key = EVP_PKEY_new();
        if( !this->key ){
            DH_free(parameter);
            vverbose << "--> [CipherDH][Costructor] Fatal Error, unable to allocate new key" << '\n';
            exit(1);
        }


        if( EVP_PKEY_set1_DH(this->key,parameter) != 1 ){
            DH_free(parameter);
            vverbose << "--> [CipherDH][Costructor] Fatal Error, unable to generate the key" << '\n';
            exit(1);
        }

        DH_free(parameter);

    }

    CipherDH::~CipherDH(){

        if( this->key )
            EVP_PKEY_free(this->key);
        vverbose << "--> [CipherDH][Destructor] diffie-hellman parameters destroyed" << '\n';

    }

    NetMessage* CipherDH::generatePartialKey(const char* i){

        //ephemeral key generation

        if( !this->key ){
            verbose<<"-->[CipherDH][generatePartialKey] Error, unable to find dh parameters. You need to call CipherDH::init()"<<'\n';
            return nullptr;
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(this->key, nullptr);
        if( this->sessionKey ){
            verbose<<"-->[CipherDH][generatePartialKey] Error, a pending session exists. Use generateSessionKey() before o stash()"<<'\n';
            return nullptr;
        }

        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_keygen(ctx, &(this->sessionKey));

        string file = "data/temp/param";
        file.append(i).append(".pem");
        FILE* pubStore = fopen( file.c_str(),"w+");
        if( !pubStore ){
            verbose<<"-->[CipherDH][generatePartialKey] Error, unable to extract diffie-hellman partial key"<<'\n';
            EVP_PKEY_free(this->sessionKey);
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }

        if( PEM_write_PUBKEY( pubStore , this->sessionKey ) != 1 ){
            verbose<<"-->[CipherDH][generatePartialKey] Error, unable to store diffie-hellman partial key"<<'\n';
            fclose(pubStore);
            EVP_PKEY_free(this->sessionKey);
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }
        fclose(pubStore);
        EVP_PKEY_CTX_free(ctx);
        std::ifstream paramRead;
        paramRead.open(file.c_str());
        if( !paramRead ){
            verbose<<"-->[CipherDH][generatePartialKey] Error, unable to load diffie-hellman partial key"<<'\n';
            return nullptr;
        }

        paramRead.seekg( 0, std::ios::end );
        int len = paramRead.tellg();
        paramRead.seekg( 0, std::ios::beg );
        unsigned char* param = new unsigned char[len];

        if( !param){
            verbose<<"--> [CipherDH][generatePartialKey] Fatal error. Unable to allocate memory"<<'\n';
            paramRead.close();
            return nullptr;
        }
        paramRead.read( (char*)param, len );
        paramRead.close();
        remove(file.c_str() );
        vverbose<<"-->[CipherDH][generatePartialKey]  Diffie-Hellman parameter generated."<<'\n';

        return new NetMessage( param , len );

    }

    SessionKey* CipherDH::generateSessionKey( unsigned char *advKey, int len , const char* i ) {

        string file = "data/temp/partial";
        file.append(i).append(".pem");

        std::ofstream partialWrite(file);
        partialWrite.write((char*)advKey,len);
        partialWrite.close();

        FILE* shared = fopen( file.c_str(), "r" );
        if( !shared ){
            verbose<<"-->[CipherDH][generateSessionKey]  Error unable to find the partial key"<<'\n';
            return nullptr;
        }
        EVP_PKEY* advPublicKey = PEM_read_PUBKEY( shared , nullptr, nullptr, nullptr );
        if( !advPublicKey ){
            verbose<<"-->[CipherDH][generateSessionKey]  Error unable to load the partial key"<<'\n';
            fclose(shared);
            return nullptr;
        }
        fclose(shared);
        remove(file.c_str() );

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new( this->sessionKey , nullptr );
        if( !ctx ){
            verbose<<"-->[CipherDH][generateSessionKey]  Error during the allocation of context"<<'\n';
            return nullptr;
        }
        if( EVP_PKEY_derive_init(ctx) <= 0){
            verbose<<"-->[CipherDH][generateSessionKey]  Error during the preparation of context"<<'\n';
            return nullptr;
        }
        if( EVP_PKEY_derive_set_peer( ctx, this->sessionKey ) <= 0){
            verbose<<"-->[CipherDH][generateSessionKey]  Error during the initialization of context"<<'\n';
            return nullptr;
        }
        size_t newLen;
        EVP_PKEY_derive(ctx,nullptr, &newLen);
        cout<<newLen<<endl;
        unsigned char* completeKey = new unsigned char[int(newLen)];
        if( !completeKey ){
            verbose<<"-->[CipherDH][generateSessionKey]  Error during the allocation of memory"<<'\n';
            return nullptr;
        }

        if( EVP_PKEY_derive(ctx,completeKey,&newLen) <= 0){
            verbose<<"-->[CipherDH][generateSessionKey]  Error during the derivation of the key"<<'\n';
            return nullptr;
        };

        //  TODO: HASH AND SEPARATION
        SessionKey* ret = new SessionKey;
        ret->sessionKey = completeKey;
        ret->sessionKeyLen = newLen;

        return ret;

    }


    void CipherDH::test(){
        CipherDH* dh = new CipherDH( "server" , true );
        CipherDH* dh2 = new CipherDH( "bob", false );

        NetMessage* net = dh->generatePartialKey("x");
        NetMessage* net2 = dh2->generatePartialKey("y");

        SessionKey* x = dh->generateSessionKey( net2->getMessage(), net2->length(),"x");
        SessionKey* x2 = dh2->generateSessionKey(net->getMessage(), net->length(),"y");

        if(!x || !x2){
            verbose<<"Error, during the generation of key"<<'\n';
            return;
        }

        if( !x->sessionKeyLen || ! x2->sessionKeyLen ){
            verbose<<"Error, message not created"<<'\n';
            return;
        }
        if( x->sessionKeyLen != x2->sessionKeyLen ) {
            verbose << "Error, lengths don't match" << '\n';
            return;
        }
        for( int a= 0; a<x->sessionKeyLen;a++)
            if( x->sessionKey[a] |= x2->sessionKey[a] ) {
                cout << "Error, key not matching in position: " << a << endl;
                return;
            }
        verbose<<"Success"<<'\n';

        delete[] x->sessionKey;
        delete[] x2->sessionKey;
        delete net;
        delete x;
        delete dh;

    }
}

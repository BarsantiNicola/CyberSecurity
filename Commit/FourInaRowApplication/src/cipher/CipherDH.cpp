
#include "CipherDH.h"

namespace cipher{

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                   COSTRUCTORS/DESTRUCTORS                                 //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    CipherDH::CipherDH() {

       this->ephemeralKey = nullptr;

    }

    CipherDH::~CipherDH(){

        if( this->ephemeralKey )
            EVP_PKEY_free(this->ephemeralKey);

        vverbose << "--> [CipherDH][Destructor] diffie-hellman parameters destroyed" << '\n';

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                     PRIVATE FUNCTIONS                                     //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  the function apply an hash on the given string and generate a set of parameters for AES encryption
    SessionKey* CipherDH::generateKeys( unsigned char *value, int len ) {

        if( !value || len <1 ){

            verbose<<"--> [CipherDH][generateKeys] Invalid arguments, operation aborted"<<'\n';
            return nullptr;

        }

        vverbose<<"--> [CipherDH][generateKeys] Generation of session parameters"<<'\n';
        unsigned char* hashed;
        unsigned char* sessionKey = nullptr;
        unsigned char* iv = nullptr;
        unsigned char* seed = nullptr;
        unsigned char* splittedValue = nullptr;

        try{

            sessionKey = new unsigned char[32];
            iv = new unsigned char[16];
            seed = new unsigned char[16];
            splittedValue = new unsigned char[128];

        }catch( bad_alloc e ){

            verbose<<"--> [CipherDH][generateKeys] Invalid arguments, operation aborted"<<'\n';
            if( !sessionKey ) delete[] sessionKey;
            if( !iv ) delete[] iv;
            if( !seed ) delete[] seed;
            if( !splittedValue ) delete[] splittedValue;
            return nullptr;

        }

        for( int a = 0; a<2; a++ ){

            for( int b = 0; b<128; b++ )
                splittedValue[b] = value[ a*128+b];

            hashed = CipherHASH::hashFunction( splittedValue, 128 );

            if( a )
                for( int b = 0; b<16;b++) {

                    iv[b] = hashed[b];
                    seed[b] = hashed[16 + b];

                }
            else
                for (int b = 0; b < 32; b++)
                    sessionKey[b] = hashed[b];

            delete[] hashed;

        }

        delete[] splittedValue;

        SessionKey* ret = new SessionKey;
        ret->sessionKey = sessionKey;
        ret->sessionKeyLen = 32;
        ret->iv = iv;
        ret->ivLen = 16;
        ret->seed = seed;
        ret->seedLen = 16;

        vverbose<<"--> [CipherDH][generateKeys] Session parameters correctly created"<<'\n';
        return ret;

    }

    DH* CipherDH::get_dh2048_auto(){

        static unsigned char dhp_2048[] = {
                0xF9, 0xEA, 0x2A, 0x73, 0x80, 0x26, 0x19, 0xE4, 0x9F, 0x4B,
                0x88, 0xCB, 0xBF, 0x49, 0x08, 0x60, 0xC5, 0xBE, 0x41, 0x42,
                0x59, 0xDB, 0xEC, 0xCA, 0x1A, 0xC9, 0x90, 0x9E, 0xCC, 0xF8,
                0x6A, 0x3B, 0x60, 0x5C, 0x14, 0x86, 0x19, 0x09, 0x36, 0x29,
                0x39, 0x36, 0x21, 0xF7, 0x55, 0x06, 0x1D, 0xA3, 0xED, 0x6A,
                0x16, 0xAB, 0xAA, 0x18, 0x2B, 0x29, 0xE9, 0x64, 0x48, 0x67,
                0x88, 0xB4, 0x80, 0x46, 0xFD, 0xBF, 0x47, 0x17, 0x91, 0x4A,
                0x9C, 0x06, 0x0A, 0x58, 0x23, 0x2B, 0x6D, 0xF9, 0xDD, 0x1D,
                0x93, 0x95, 0x8F, 0x76, 0x70, 0xC1, 0x80, 0x10, 0x4B, 0x3D,
                0xAC, 0x08, 0x33, 0x7D, 0xDE, 0x38, 0xAB, 0x48, 0x7F, 0x38,
                0xC4, 0xA6, 0xD3, 0x96, 0x4B, 0x5F, 0xF9, 0x4A, 0xD7, 0x4D,
                0xAE, 0x10, 0x2A, 0xD9, 0xD3, 0x4A, 0xF0, 0x85, 0x68, 0x6B,
                0xDE, 0x23, 0x9A, 0x64, 0x02, 0x2C, 0x3D, 0xBC, 0x2F, 0x09,
                0xB3, 0x9E, 0xF1, 0x39, 0xF6, 0xA0, 0x4D, 0x79, 0xCA, 0xBB,
                0x41, 0x81, 0x02, 0xDD, 0x30, 0x36, 0xE5, 0x3C, 0xB8, 0x64,
                0xEE, 0x46, 0x46, 0x5C, 0x87, 0x13, 0x89, 0x85, 0x7D, 0x98,
                0x0F, 0x3C, 0x62, 0x93, 0x83, 0xA0, 0x2F, 0x03, 0xA7, 0x07,
                0xF8, 0xD1, 0x2B, 0x12, 0x8A, 0xBF, 0xE3, 0x08, 0x12, 0x5F,
                0xF8, 0xAE, 0xF8, 0xCA, 0x0D, 0x52, 0xBC, 0x37, 0x97, 0xF0,
                0xF5, 0xA7, 0xC3, 0xBB, 0xC0, 0xE0, 0x54, 0x7E, 0x99, 0x6A,
                0x75, 0x69, 0x17, 0x2D, 0x89, 0x1E, 0x64, 0xE5, 0xB6, 0x99,
                0xCE, 0x84, 0x08, 0x1D, 0x89, 0xFE, 0xBC, 0x80, 0x1D, 0xA1,
                0x14, 0x1C, 0x66, 0x22, 0xDA, 0x35, 0x1D, 0x6D, 0x53, 0x98,
                0xA8, 0xDD, 0xD7, 0x5D, 0x99, 0x13, 0x19, 0x3F, 0x58, 0x8C,
                0x4F, 0x56, 0x5B, 0x16, 0xE8, 0x59, 0x79, 0x81, 0x90, 0x7D,
                0x7C, 0x75, 0x55, 0xB8, 0x50, 0x63
        };

        static unsigned char dhg_2048[] = {
                0x02
        };

        DH *dh = DH_new();
        BIGNUM *p, *g;

        if (dh == NULL)
            return NULL;

        p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
        g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);

        if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
            DH_free(dh);
            BN_free(p);
            BN_free(g);
            return NULL;
        }

        return dh;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                      PUBLIC FUNCTIONS                                     //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  the class use Diffie-Hellman parameters to generate a token to share with a peer to generate a shared session key.
    //  It don't allow to be used if another keys generation is performing, you need to end the previous key generation
    //  or in case of abort to use the stash() function the reset the class
    NetMessage* CipherDH::generatePartialKey(){

        vverbose<<"--> [CipherDH][generatePartialKey] Starting generation of ephemeral key"<<'\n';
        if( this->ephemeralKey ){

            verbose<<"--> [CipherDH][generatePartialKey] Error, another session already open. Use generateSessionKey() or stash() before" << '\n';
            return nullptr;

        }

        EVP_PKEY *params = EVP_PKEY_new();
        if( !params ){

            verbose<<"--> [CipherDH][generatePartialKey] Error, during the creation of diffie-hellman parameters"<<'\n';
            return nullptr;

        }

        DH* temp = get_dh2048_auto();
        if( 1 != EVP_PKEY_set1_DH( params, temp ) ){

            verbose<<"--> [CipherDH][generatePartialKey] Error, during the merging of diffie-hellman parameters"<<'\n';
            EVP_PKEY_free( params );
            return nullptr;

        }
        DH_free( temp );

        EVP_PKEY_CTX *DHctx;
        if( !( DHctx = EVP_PKEY_CTX_new( params, nullptr ))){

            verbose<<"--> [CipherDH][generatePartialKey] Error, during the creation of diffie-hellman context"<<'\n';
            EVP_PKEY_free( params );
            return nullptr;

        }

        EVP_PKEY_free( params );

        if( 1 != EVP_PKEY_keygen_init(DHctx) ){

            verbose<<"--> [CipherDH][generatePartialKey] Error, during the initialization of diffie-hellman parameters"<<'\n';
            EVP_PKEY_CTX_free( DHctx );
            return nullptr;

        }

        if( 1 != EVP_PKEY_keygen( DHctx, &( this->ephemeralKey )) ){

            verbose<<"--> [CipherDH][generatePartialKey] Error, during the generation of the ephemeral key"<<'\n';
            EVP_PKEY_CTX_free( DHctx );
            return nullptr;

        }
        vverbose<<"--> [CipherDH][generatePartialKey] Exporting of generated public key"<<'\n';

        string file = "data/temp/param.pem";
        FILE* pubStore = fopen( file.c_str(),"w+");
        if( !pubStore ){

            verbose<<"--> [CipherDH][generatePartialKey] Error, unable to extract diffie-hellman partial key"<<'\n';
            EVP_PKEY_free( this->ephemeralKey );
            this->ephemeralKey = nullptr;
            EVP_PKEY_CTX_free( DHctx );
            return nullptr;

        }

        if( PEM_write_PUBKEY( pubStore , this->ephemeralKey ) != 1 ){

            verbose<<"--> [CipherDH][generatePartialKey] Error, unable to store diffie-hellman partial key"<<'\n';
            fclose( pubStore );
            remove( file.c_str() );
            EVP_PKEY_free( this->ephemeralKey );
            this->ephemeralKey = nullptr;
            EVP_PKEY_CTX_free( DHctx );
            return nullptr;

        }

        fclose( pubStore );
        EVP_PKEY_CTX_free( DHctx );
        std::ifstream paramRead;
        paramRead.open( file.c_str() );

        if( !paramRead ){

            verbose<<"--> [CipherDH][generatePartialKey] Error, unable to load diffie-hellman partial key"<<'\n';
            EVP_PKEY_free(this->ephemeralKey);
            this->ephemeralKey = nullptr;
            remove( file.c_str() );
            return nullptr;

        }

        paramRead.seekg( 0, std::ios::end );
        int len = paramRead.tellg();
        paramRead.seekg( 0, std::ios::beg );
        unsigned char* param;

        try{

            param = new unsigned char[len];

        }catch( bad_alloc e ){

            verbose<<"--> [CipherDH][generatePartialKey] Fatal error. Unable to allocate memory"<<'\n';
            paramRead.close();
            remove( file.c_str() );
            EVP_PKEY_free(this->ephemeralKey);
            this->ephemeralKey = nullptr;
            return nullptr;

        }

        paramRead.read( (char*)param, len );
        paramRead.close();
        remove( file.c_str() );
        vverbose<<"--> [CipherDH][generatePartialKey] Partial Diffie-Hellman parameter generated"<<'\n';

        try {

            NetMessage* ret = new NetMessage(param, len);
            delete[] param;
            return ret;

        }catch( bad_alloc e ){

            verbose<<"--> [CipherDH][generatePartialKey] Fatal error. Unable to allocate memory"<<'\n';
            return nullptr;

        }

    }

    //  reset the current key generation allowing to restart another one
    void CipherDH::stash() {

        vverbose<<"--> [CipherDH][generatePartialKey] Force removing of DH partial values"<<'\n';

        if( this->ephemeralKey ) {

            EVP_PKEY_free(this->ephemeralKey);
            this->ephemeralKey = nullptr;
            vverbose<<"--> [CipherDH][generatePartialKey] CipherDH reset completed" <<'\n';

        }

    }

    //  the function use the token generated by the other peer to create a new session key. The function don't
    //  allow to be used before the generatePartialKey
    SessionKey* CipherDH::generateSessionKey( unsigned char *advKey, int len ) {

        if( !this->ephemeralKey ){

            verbose<<"--> [CipherDH][generateSessionKey]  You must initialize the ephemeral key. Use generatePartialKey() before"<<'\n';
            return nullptr;

        }

        vverbose<<"--> [CipherDH][generatePartialKey] Starting derivation of keys"<<'\n';
        string file = "data/temp/partial.pem";

        std::ofstream partialWrite(file);
        partialWrite.write((char*)advKey,len);
        partialWrite.close();

        FILE* shared = fopen( file.c_str(), "r" );
        if( !shared ){

            verbose<<"--> [CipherDH][generateSessionKey]  Error unable to find the partial key"<<'\n';
            EVP_PKEY_free( this->ephemeralKey );
            this->ephemeralKey = nullptr;
            remove(file.c_str());
            return nullptr;

        }

        EVP_PKEY* advPublicKey = PEM_read_PUBKEY( shared , nullptr, nullptr, nullptr );
        if( !advPublicKey ){

            verbose<<"--> [CipherDH][generateSessionKey]  Error unable to load the partial key"<<'\n';
            fclose(shared);
            remove(file.c_str());
            EVP_PKEY_free( this->ephemeralKey );
            this->ephemeralKey = nullptr;
            return nullptr;

        }

        fclose(shared);
        remove(file.c_str());

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new( this->ephemeralKey , nullptr );
        if( !ctx ){

            verbose<<"--> [CipherDH][generateSessionKey]  Error during the allocation of context"<<'\n';
            EVP_PKEY_free( this->ephemeralKey );
            this->ephemeralKey = nullptr;
            return nullptr;

        }

        if( EVP_PKEY_derive_init(ctx) <= 0){

            verbose<<"--> [CipherDH][generateSessionKey]  Error during the preparation of context"<<'\n';
            EVP_PKEY_free( this->ephemeralKey );
            this->ephemeralKey = nullptr;
            return nullptr;

        }

        if( EVP_PKEY_derive_set_peer( ctx, advPublicKey ) <= 0){

            verbose<<"--> [CipherDH][generateSessionKey]  Error during the initialization of context"<<'\n';
            EVP_PKEY_free( this->ephemeralKey );
            this->ephemeralKey = nullptr;
            return nullptr;

        }

        size_t newLen;
        EVP_PKEY_derive(ctx,nullptr, &newLen);
        unsigned char* completeKey;

        try {

            completeKey = new unsigned char[int(newLen)];

        }catch( bad_alloc e ){

            verbose<<"-->[CipherDH][generateSessionKey]  Error during the allocation of memory"<<'\n';
            EVP_PKEY_free( this->ephemeralKey );
            this->ephemeralKey = nullptr;
            return nullptr;

        }

        if( EVP_PKEY_derive(ctx,completeKey,&newLen) <= 0){

            verbose<<"--> [CipherDH][generateSessionKey]  Error during the derivation of the key"<<'\n';
            EVP_PKEY_free( this->ephemeralKey );
            this->ephemeralKey = nullptr;
            return nullptr;

        };

        EVP_PKEY_free( this->ephemeralKey );
        this->ephemeralKey = nullptr;
        vverbose<<"--> [CipherDH][generateSessionKey] Session keys correctly derived"<<'\n';
        return generateKeys( completeKey, newLen );

    }

}

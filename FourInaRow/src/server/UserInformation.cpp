
#include "UserInformation.h"

namespace server{

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                    CONSTRUCTORS/DESTRUCTORS                               //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    UserInformation::UserInformation( int socket , string username ){

        this->username = username;
        this->status = CONNECTED;
        this->socket = socket;
        this->sessionKey = nullptr;

    }

    UserInformation::UserInformation( int socket, string username, UserStatus status,  cipher::SessionKey* key ){

        this->socket = socket;
        this->username = username;
        this->status = status;

        if( key ){

            try {

                this->sessionKey = new cipher::SessionKey();
                this->sessionKey->sessionKey = key->sessionKey;
                this->sessionKey->sessionKeyLen = key->sessionKeyLen;
                this->sessionKey->iv = key->iv;
                this->sessionKey->ivLen = key->ivLen;

            }catch( bad_alloc e ){

                verbose<<"--> [UserInformation][Constructor] Error during memory allocation. Operation aborted"<<'\n';
                this->sessionKey = nullptr;
            }

        }else
            this->sessionKey = nullptr;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           SETTERS                                         //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    bool UserInformation::setSessionKey( cipher::SessionKey* key ){

        if( this->sessionKey ) {

            vverbose<<"-->[UserInformation][setSessionKey] The client has already a session key. Operation aborted"<<'\n';
            return false;

        }

        if( key ){

            try {

                this->sessionKey = new cipher::SessionKey();
                this->sessionKey->sessionKey = key->sessionKey;
                this->sessionKey->sessionKeyLen = key->sessionKeyLen;
                this->sessionKey->iv = key->iv;
                this->sessionKey->ivLen = key->ivLen;
                return true;

            }catch( bad_alloc e ){

                verbose<<"--> [UserInformation][setSessionKey] Error during memory allocation. Operation aborted"<<'\n';
                this->sessionKey = nullptr;
                return false;

            }

        }else
            this->sessionKey = nullptr;

        vverbose<<"-->[UserInformation][setSessionKey] Invalid arguments. Operation aborted"<<'\n';
        return false;
    }

    //  sets the status of the user accordingly of the possible change of the status available from the client commands
    bool UserInformation::setStatus( UserStatus status ){

        switch( this->status ){

            case CONNECTED:

                if( status != LOGGED ){

                    verbose<<"--> [UserInformation][setStatus] Error, trying to perform an invalid status change"<<'\n';
                    return false;

                }
                break;

            case LOGGED:
                break;

            case WAIT_MATCH:

                if( status == CONNECTED ){

                    verbose<<"--> [UserInformation][setStatus] Error, trying to perform an invalid status change"<<'\n';
                    return false;

                }
                break;

            case PLAY:

                if( status == CONNECTED || status == WAIT_MATCH ){

                    verbose<<"--> [UserInformation][setStatus] Error, trying to perform an invalid status change"<<'\n';
                    return false;

                }
                break;

            default:

                verbose<<"--> [UserInformation][setStatus] Error, Invalid status"<<'\n';
                return false;

        }

        this->status = status;
        return true;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           GETTERS                                         //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    int UserInformation::getSocket() {
        return this->socket;
    }

    UserStatus* UserInformation::getStatus(){

        try {

            return new UserStatus(this->status);

        }catch( bad_alloc e ){

            verbose<<"--> [UserInformation][getStatus] Error during memory allocation. Operation aborted"<<'\n';
            return nullptr;

        }

    }

    string UserInformation::getUsername(){

        return this->username;

    }
    /*
    unsigned char* sessionKey;
    unsigned int sessionKeyLen;
    unsigned char* iv;
    unsigned int ivLen;
    unsigned char* seed;
    unsigned int seedLen;*/

    cipher::SessionKey* UserInformation::getSessionKey(){

        unsigned char *sKey = nullptr;
        unsigned char *iv = nullptr;
        unsigned char *seed = nullptr;
        cipher::SessionKey *key = nullptr;

        try {

            key = new cipher::SessionKey();

            sKey = new unsigned char[this->sessionKey->sessionKeyLen];
            for (int a = 0; a < this->sessionKey->sessionKeyLen; a++)
                sKey[a] = this->sessionKey->sessionKey[a];

            iv = new unsigned char[this->sessionKey->ivLen];
            for (int a = 0; a < this->sessionKey->ivLen; a++)
                iv[a] = this->sessionKey->iv[a];

            seed = new unsigned char[this->sessionKey->seedLen];
            for (int a = 0; a < this->sessionKey->seedLen; a++)
                seed[a] = this->sessionKey->seed[a];

            key->sessionKey = sKey;
            key->sessionKeyLen = this->sessionKey->sessionKeyLen;
            key->iv = iv;
            key->ivLen = this->sessionKey->ivLen;
            key->seed = seed;
            key->seedLen = this->sessionKey->seedLen;

            return key;

        }catch( bad_alloc e ){

            verbose<<"--> [UserInformation][getSessionKey] Error during memory allocation. Operation aborted"<<'\n';
            if( key ) delete key;
            if( sKey ) delete[] sKey;
            if( iv ) delete[] iv;

            return nullptr;

        }

    }

}
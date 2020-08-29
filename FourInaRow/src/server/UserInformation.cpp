
#include "UserInformation.h"

namespace server{

    UserInformation::UserInformation( int socket , string username ){

        this->username = username;
        this->status = CONNECTED;
        this->socket = socket;
        this->nonce = nullptr;
        this->sessionKey = nullptr;

    }

    UserInformation::UserInformation( int socket, string username, UserStatus status,  cipher::SessionKey* key, int* nonce ){

        this->socket = socket;
        this->username = username;
        this->status = status;

        if( key ){
            this->sessionKey = new cipher::SessionKey();
            this->sessionKey->sessionKey = key->sessionKey;
            this->sessionKey->sessionKeyLen = key->sessionKeyLen;
            this->sessionKey->iv = key->iv;
            this->sessionKey->ivLen = key->ivLen;
        }else
            this->sessionKey = nullptr;

        if( nonce )
            this->nonce = new int(*nonce);
        else
            this->nonce = nullptr;

    }

    bool UserInformation::setSessionKey( cipher::SessionKey* key ){

        if( this->sessionKey ) {

            verbose<<"-->[UserInformation][setSessionKey] Error, the client has already a session key setted"<<'\n';
            return false;

        }

        if( key ){

            this->sessionKey = new cipher::SessionKey();
            this->sessionKey->sessionKey = key->sessionKey;
            this->sessionKey->sessionKeyLen = key->sessionKeyLen;
            this->sessionKey->iv = key->iv;
            this->sessionKey->ivLen = key->ivLen;
            return true;

        }else {

            this->sessionKey = nullptr;
            return false;

        }

    }

    bool UserInformation::setStatus( UserStatus status ){

        switch( this->status ){
            case CONNECTED:
                if( status != LOGGED ){
                    verbose<<"--> [UserInformation][setStatus] Error, trying to perform an invalid status change"<<'\n';
                    return false;
                }
                break;

            case LOGGED:
                if( status == PLAY ){
                    verbose<<"--> [UserInformation][setStatus] Error, trying to perform an invalid status change"<<'\n';
                    return false;
                }
                break;

            case WAIT_MATCH:
                if( status == LOGGED ){
                    verbose<<"--> [UserInformation][setStatus] Error, trying to perform an invalid status change"<<'\n';
                    return false;
                }
                break;

            case PLAY:
                if( status != LOGGED ){
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

    void UserInformation::setNonce( int nonce ) {

        if( this->nonce == nullptr )
            this->nonce = new int(nonce);
        *(this->nonce) = nonce;

    }

    int UserInformation::getSocket() {
        return this->socket;
    }

    UserStatus* UserInformation::getStatus(){

        return new UserStatus( this->status );

    }

    string UserInformation::getUsername(){

        return this->username;

    }


    int* UserInformation::getNonce() {

        if( this->nonce )
            return new int(*(this->nonce));

        return nullptr;

    }

    cipher::SessionKey* UserInformation::getSessionKey(){

        return this->sessionKey;

    }

}
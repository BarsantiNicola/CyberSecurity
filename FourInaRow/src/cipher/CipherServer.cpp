
#include "CipherServer.h"

namespace cipher{

    CipherServer::CipherServer(){

        this->rsa = new CipherRSA("server", "serverPassword", true );
        this->dh  = new CipherDH();
        this->aes = new CipherAES();
        if( !this->rsa || !this->dh || !this->aes ){

            verbose<<"-->[CipherServer][Costructor] Fatal error, unable to load cipher suites"<<'\n';
            exit(1);

        }

    }

    CipherServer::~CipherServer(){
        delete this->rsa;
        delete this->dh;
        delete this->aes;
    }

    bool CipherServer::toSecureForm( Message* message , SessionKey* key ){

        if( message == nullptr ){

            verbose<<"-->[CipherServer][toSecureForm] Error, null pointer message"<<'\n';
            return false;

        }

        Message* app;

        switch( message->getMessageType()){

            case CERTIFICATE:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case LOGIN_OK:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case LOGIN_FAIL:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case KEY_EXCHANGE:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case RANK_LIST:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->encryptMessage(*message);
                if( app == nullptr )
                    return false;

                message->setSignature( app->getSignature(), app->getSignatureLen() );
                message->setRankList( app->getRankList(), app->getRankListLen() );
                delete app;
                break;

            case USER_LIST:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->encryptMessage(*message);
                if( app == nullptr )
                    return false;

                message->setSignature( app->getSignature(), app->getSignatureLen() );
                message->setUserList( app->getUserList(), app->getUserListLen() );
                delete app;

                break;

            case MATCH:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case GAME_PARAM:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case ACCEPT:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case REJECT:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case WITHDRAW_OK:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case DISCONNECT:

                if( !this->rsa->sign(message))
                    return false;
                break;

            case LOGOUT_OK:

                if( !key ) return false;
                this->aes->modifyParam( key );
                app = this->aes->encryptMessage(*message);
                if( app == nullptr ) {
                    return false;
                }
                message->setSignature( app->getSignature(), app->getSignatureLen() );
                delete app;

                break;

            case ERROR:

                if( !this->rsa->sign(message))
                    return false;
                break;

            default:
                vverbose<<"--> [CipherServer][toSecureForm] Error, messageType not supported:"<<message->getMessageType()<<'\n';
                return false;
        }

        return true;

    }
    bool CipherServer::fromSecureForm( Message* message , string username , SessionKey* key ){

        if( !message ){

            verbose<<"-->[CipherServer][fromSecureForm] Error, null pointer message"<<'\n';
            return false;

        }

        Message* app;
        switch( message->getMessageType()){

            case LOGIN_REQ:

                if( !this->rsa->loadUserKey(username ))
                    return false;

                return this->rsa->serverVerifySignature(*message, message->getUsername());

            case KEY_EXCHANGE:

                return this->rsa->serverVerifySignature(*message, username);

            case USER_LIST_REQ:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;
                message->setUserList( app->getUserList(), app->getUserListLen() );
                delete app;
                break;

            case RANK_LIST_REQ:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;
                message->setUserList( app->getRankList(), app->getRankListLen() );
                delete app;
                break;

            case MATCH:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;
                delete app;
                break;

            case ACCEPT:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;

                delete app;
                break;

            case REJECT:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;

                delete app;
                break;

            case LOGOUT_REQ:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ){

                    return false;
                }
                delete app;
                break;

            case DISCONNECT:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ){

                    return false;
                }
                delete app;
                break;

            case WITHDRAW_REQ:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ){

                    return false;
                }
                delete app;
                break;
            case GAME:
                if( !key ) return false;

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ){
                    return false;
                }
                message->setChosenColumn( app->getChosenColumn(), app->getChosenColumnLength());
                delete app;
                return this->rsa->serverVerifySignature(*message, username );
                
            default:
                verbose<<"--> [CipherServer][fromSecureForm] Error, MessageType not supported:"<<message->getMessageType()<<'\n';


        }

        return true;

    }

    NetMessage* CipherServer::getServerCertificate(){

        return this->rsa->getServerCertificate();

    }

    SessionKey* CipherServer::getSessionKey( unsigned char* param , unsigned int paramLen ){

        return this->dh->generateSessionKey( param , paramLen );

    }

    NetMessage* CipherServer::getPartialKey(){

        return this->dh->generatePartialKey();

    }

    NetMessage* CipherServer::getPubKey( string username ){

        EVP_PKEY* key = this->rsa->getUserKey( username );

        string path = "data/temp/";
        path.append(username);
        path.append(".pem");

        FILE* f = fopen(path.c_str() , "w");
        if( !f ){

            verbose<<"-->[CipherServer][getPubKey] Error, unable to find temp file"<<'\n';
            return nullptr;

        }

        PEM_write_PUBKEY(f, key );
        fclose(f);

        std::ifstream pubKeyRead;
        pubKeyRead.open(path.c_str() );
        if( !pubKeyRead ){
            verbose<<"--> [CipherServer][getPubKey] Fatal Error. Unable to find: "<<path<<'\n';
            return nullptr;
        }

        pubKeyRead.seekg( 0, std::ios::end );
        int len = pubKeyRead.tellg();

        unsigned char* pubKey;
        pubKeyRead.seekg( 0, std::ios::beg );
        pubKey = new unsigned char[ len ];
        if( !pubKey ){
            verbose<<"--> [CipherServer][getPubKey] Fatal error. Unable to allocate memory"<<'\n';
            pubKeyRead.close();
            return nullptr;
        }
        pubKeyRead.read( (char*)pubKey, len);
        pubKeyRead.close();
        remove( path.c_str() );

        return new NetMessage( pubKey, len);
    }

}
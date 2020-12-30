
#include "CipherServer.h"

namespace cipher{


    CipherServer::CipherServer(){

        this->rsa = new CipherRSA("server", "serverPassword", true );
        this->dh  = new CipherDH();
        this->aes = new CipherAES();

        if( !this->rsa || !this->dh || !this->aes ){

            verbose<<"--> [CipherServer][Costructor] Fatal error, unable to load cipher suites"<<'\n';
            exit(1);

        }

    }

    CipherServer::~CipherServer(){

        if( this->rsa ) delete this->rsa;
        if( this->dh )  delete this->dh;
        if( this->aes ) delete this->aes;

    }

    //  the function convert a message into the secure domain. Basing on the type of message it applies RSA methods to generate
    //  a signature or by AES-256 GCM creates a signature and encrypts the needed fields of the message.
    bool CipherServer::toSecureForm( Message* message , SessionKey* key ){

        if( !message ){

            verbose<<"--> [CipherServer][toSecureForm] Error invalid arguments, operation aborted"<<'\n';
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

                if( !key ){

                    verbose<<"--> [CipherServer][toSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                if( !this->aes->modifyParam( key )) return false;

                app = this->aes->encryptMessage(*message);
                if( !app ){

                    verbose<<"--> [CipherServer][toSecureForm] Error during the AES encryption operation aborted"<<'\n';
                    return false;

                }

                message->setSignature( app->getSignature(), app->getSignatureLen() );
                message->setRankList(  app->getRankList(), app->getRankListLen() );
                delete app;
                break;

            case USER_LIST:

                if( !key ){

                    verbose<<"--> [CipherServer][toSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                if( !this->aes->modifyParam( key )) return false;

                app = this->aes->encryptMessage(*message);
                if( !app ){

                    verbose<<"--> [CipherServer][toSecureForm] Error during the AES encryption operation aborted"<<'\n';
                    return false;

                }

                message->setSignature( app->getSignature(), app->getSignatureLen() );
                message->setUserList( app->getUserList(), app->getUserListLen() );
                delete app;

                break;

            case MATCH:

                if( !key ){

                    verbose<<"--> [CipherServer][toSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                if( !this->aes->modifyParam( key )) return false;

                app = this->aes->encryptMessage(*message);
                if( !app ){

                    verbose<<"--> [CipherServer][toSecureForm] Error during the AES encryption operation aborted"<<'\n';
                    return false;

                }

                message->setSignature( app->getSignature(), app->getSignatureLen() );
                delete app;

                break;

            case GAME_PARAM:

                if( !key ){

                    verbose<<"--> [CipherServer][toSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                if( !this->aes->modifyParam( key )) return false;

                app = this->aes->encryptMessage(*message);
                if( !app ){

                    verbose<<"--> [CipherServer][toSecureForm] Error during the AES encryption operation aborted"<<'\n';
                    return false;

                }

                message->setNetInformations( app->getNetInformations(), app->getNetInformationsLength());
                message->setSignature( app->getSignature(), app->getSignatureLen() );
                delete app;

                break;

            case ACCEPT:

                if( !key ){

                    verbose<<"--> [CipherServer][toSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                if( !this->aes->modifyParam( key )) return false;

                app = this->aes->encryptMessage(*message);
                if( !app ){

                    verbose<<"--> [CipherServer][toSecureForm] Error during the AES encryption operation aborted"<<'\n';
                    return false;

                }

                message->setSignature( app->getSignature(), app->getSignatureLen() );
                delete app;

                break;

            case REJECT:

                if( !key ){

                    verbose<<"--> [CipherServer][toSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                if( !this->aes->modifyParam( key )) return false;

                app = this->aes->encryptMessage(*message);
                if( !app ){

                    verbose<<"--> [CipherServer][toSecureForm] Error during the AES encryption operation aborted"<<'\n';
                    return false;

                }

                message->setSignature( app->getSignature(), app->getSignatureLen() );
                delete app;

                break;

            case WITHDRAW_REQ:

                if( !key ){

                    verbose<<"--> [CipherServer][toSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                if( !this->aes->modifyParam( key )) return false;

                app = this->aes->encryptMessage(*message);
                if( !app ){

                    verbose<<"--> [CipherServer][toSecureForm] Error during the AES encryption operation aborted"<<'\n';
                    return false;

                }

                message->setSignature( app->getSignature(), app->getSignatureLen() );
                delete app;

                break;

            case WITHDRAW_OK:

                if( !key ){

                    verbose<<"--> [CipherServer][toSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                if( !this->aes->modifyParam( key )) return false;

                app = this->aes->encryptMessage(*message);
                if( !app ){

                    verbose<<"--> [CipherServer][toSecureForm] Error during the AES encryption operation aborted"<<'\n';
                    return false;

                }

                message->setSignature( app->getSignature(), app->getSignatureLen() );
                delete app;

                break;

            case DISCONNECT:

                if( !key ){

                    verbose<<"--> [CipherServer][toSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                if( !this->aes->modifyParam( key )) return false;

                app = this->aes->encryptMessage(*message);
                if( !app ){

                    verbose<<"--> [CipherServer][toSecureForm] Error during the AES encryption operation aborted"<<'\n';
                    return false;

                }

                message->setSignature( app->getSignature(), app->getSignatureLen() );
                delete app;

                break;

            case LOGOUT_OK:

                if( !key ){

                    verbose<<"--> [CipherServer][toSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                if( !this->aes->modifyParam( key )) return false;

                app = this->aes->encryptMessage(*message);
                if( !app ){

                    verbose<<"--> [CipherServer][toSecureForm] Error during the AES encryption operation aborted"<<'\n';
                    return false;

                }

                message->setSignature( app->getSignature(), app->getSignatureLen() );
                delete app;

                break;

            case ERROR:

                if( !this->rsa->sign(message))
                    return false;
                break;
                
            case GAME:

                if( !this->rsa->sign(message))
		            return false;
		        break;
		
            default:

                verbose<<"--> [CipherServer][toSecureForm] Error, messageType not supported:"<<message->getMessageType()<<'\n';
                return false;

        }

        vverbose<<"--> [CipherServer][toSecureForm]returning true for message type:"<<message->getMessageType()<<'\n';
        return true;

    }

    //  the function convert a message from the secure domain. Basing on the type of message it uses RSA'methods to validate the message'
    //  signature or by AES-256 GCM decrypts the needed fields and validate the message signature.
    bool CipherServer::fromSecureForm( Message* message , string username , SessionKey* key ){

        if( !message ){

            verbose<<"--> [CipherServer][toSecureForm] Error invalid arguments, operation aborted"<<'\n';
            return false;

        }

        Message* app,*newMsg;
        switch( message->getMessageType()){

            case LOGIN_REQ:

                if( !this->rsa->loadUserKey(username ))
                    return false;

                return this->rsa->serverVerifySignature(*message, message->getUsername());

            case KEY_EXCHANGE:

                return this->rsa->serverVerifySignature( *message, username );

            case USER_LIST_REQ:

                if( !key ){

                    verbose<<"--> [CipherServer][fromSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;
                delete app;

                break;

            case RANK_LIST_REQ:

                if( !key ){

                    verbose<<"--> [CipherServer][fromSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;
                delete app;

                break;

            case MATCH:

                if( !key ){

                    verbose<<"--> [CipherServer][fromSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;
                delete app;

                break;

            case ACCEPT:

                if( !key ){

                    verbose<<"--> [CipherServer][fromSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;
                delete app;

                break;

            case REJECT:

                if( !key ){

                    verbose<<"--> [CipherServer][fromSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;
                delete app;

                break;

            case LOGOUT_REQ:

                if( !key ){

                    verbose<<"--> [CipherServer][fromSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;
                delete app;

                break;

            case DISCONNECT:

                if( !key ){

                    verbose<<"--> [CipherServer][fromSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;
                delete app;

                break;

            case WITHDRAW_REQ:

                if( !key ){

                    verbose<<"--> [CipherServer][fromSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;
                delete app;

                break;

            case GAME:

                if( !key ){

                    verbose<<"--> [CipherServer][fromSecureForm] Error invalid arguments, operation aborted"<<'\n';
                    return false;

                }

                this->aes->modifyParam( key );
                app = this->aes->decryptMessage( *message );

                if( !app ) return false;

                message->setMessageType(GAME);
                message->setChosenColumn(app->getChosenColumn(), app->getChosenColumnLength());
                message->setCurrent_Token(*(app->getCurrent_Token()));
                message->setSignature(message->getSignature(),message->getSignatureLen());

                return this->rsa->serverVerifySignature(*message, username );
                
            default:

                verbose<<"--> [CipherServer][fromSecureForm] Error, MessageType not supported:"<<message->getMessageType()<<'\n';
                return false;

        }

        return true;

    }

    //  it gives the server certificate extracting it from the file-system
    NetMessage* CipherServer::getServerCertificate(){

        return this->rsa->getServerCertificate();

    }

    //  used to start the diffie-hellman algorithm to create the parameter to be send to the other end-point
    NetMessage* CipherServer::getPartialKey(){

        return this->dh->generatePartialKey();

    }

    //  used at the end of the diffie-hellman algorithm to generate a session key for AES-256 GCM
    SessionKey* CipherServer::getSessionKey( unsigned char* param , unsigned int paramLen ){

        return this->dh->generateSessionKey( param , paramLen );

    }

    //  the function extract the RSA public key of the given username then compact it in a form that can be inserted into a Message
    NetMessage* CipherServer::getPubKey( string username ){

        std::ifstream pubKeyRead;
        EVP_PKEY* key = this->rsa->getUserKey( username );
        NetMessage* message;

        if( !key ){

            verbose<<"--> [CipherServer][getPubKey] Error, unable to find the user key"<<'\n';
            return nullptr;

        }

        string path = "data/temp/";
        path.append(username);
        path.append(".pem");

        FILE* f = fopen(path.c_str() , "w");
        if( !f ){

            verbose<<"--> [CipherServer][getPubKey] Error, unable to find temp file"<<'\n';
            return nullptr;

        }

        PEM_write_PUBKEY(f, key );
        fclose(f);

        pubKeyRead.open(path.c_str() );
        if( !pubKeyRead ){

            remove( path.c_str() );
            verbose<<"--> [CipherServer][getPubKey] Fatal Error. Unable to find: "<<path<<'\n';
            return nullptr;

        }

        pubKeyRead.seekg( 0, std::ios::end );
        int len = pubKeyRead.tellg();

        unsigned char* pubKey;
        pubKeyRead.seekg( 0, std::ios::beg );

        try {

            pubKey = new unsigned char[len];

            pubKeyRead.read( (char*)pubKey, len);
            pubKeyRead.close();
            remove( path.c_str() );

            message = new NetMessage( pubKey, len);

            delete[] pubKey;
            return message;

        }catch( bad_alloc e ){

            verbose<<"--> [CipherServer][getPubKey] Fatal error. Unable to allocate memory"<<'\n';
            pubKeyRead.close();
            remove( path.c_str() );
            return nullptr;

        }

    }

}


#include "PowerClient.h"

PowerClient::PowerClient( string ipAddr, int port ){

    this->cipher = new cipher::CipherRSA( "bob", "bobPassword", false );
    this->cipher2 = new cipher::CipherRSA( "alice" , "alicePassword", false );
    this->cipherDH = new cipher::CipherDH();
    this->cipherAes = new cipher::CipherAES();
    this->manager = new ConnectionManager(false,ipAddr.c_str(),port);

    if(!this->manager->createConnectionWithServerTCP( ipAddr.c_str(), port )){

        std::cout<<"connection not created"<<endl;
        exit(1);

    }
    this->server_socket = this->manager->getserverSocket();

}

void PowerClient::sendMessage( MessageType type, bool correctness ){

    bool okSend;
    const char *m = nullptr;
    string *s;
    int idSock;
    vector<int> vect;

    Message* message = this->createMessage( type, correctness );

    this->manager->sendMessage( *message, this->server_socket, &okSend, m, 0 );


    vect = this->manager->waitForMessage( &idSock ,s );

    if( vect.size()){
        for( int sock: vect ) {
            message = this->manager->getMessage(sock);
            if( message ) {
                this->showMessage(message);
            }else
                cout<<"no message received"<<endl;

        }
    }
    vect.clear();

}

Message* PowerClient::createMessage( MessageType type, bool correctness ){

    Message* message = new Message();
    NetMessage* param;
    if( correctness )
        switch( type ){
            case utility::CERTIFICATE_REQ:
                message->setMessageType( CERTIFICATE_REQ );
                message->setNonce(0);
                break;

            case utility::LOGIN_REQ:
                message->setMessageType( LOGIN_REQ );
                message->setNonce(this->nonce);
                message->setUsername("bob" );
                this->cipher->sign( message );
                this->nonce++;
                break;

            case utility::KEY_EXCHANGE:
                message->setMessageType( KEY_EXCHANGE );
                message->setNonce(nonce);
                param = this->cipherDH->generatePartialKey();
                message->set_DH_key( param->getMessage(), param->length() );
                this->cipher->sign( message );
                this->nonce++;
                break;

            case utility::USER_LIST_REQ:
                message->setMessageType( USER_LIST_REQ );
                message->setNonce(nonce);
                message = this->cipherAes->encryptMessage(*message);
                this->nonce++;
                break;

            case utility::RANK_LIST_REQ:
                message->setMessageType( RANK_LIST_REQ );
                message->setNonce(nonce );
                message = this->cipherAes->encryptMessage(*message);
                this->nonce++;
                break;

            case utility::LOGOUT_REQ:
                message->setMessageType( LOGOUT_REQ );
                message->setNonce(nonce);
                message = this->cipherAes->encryptMessage(*message);
                this->nonce++;
                break;
        }
    else
        switch( type ){
            case utility::CERTIFICATE_REQ:
                message->setMessageType( CERTIFICATE_REQ );
                message->setNonce(1);
                break;

            case utility::LOGIN_REQ:
                message->setMessageType( LOGIN_REQ );
                message->setNonce(2);
                message->setUsername("bob" );
                this->cipher2->sign( message );
                break;

            case utility::KEY_EXCHANGE:
                message->setMessageType( KEY_EXCHANGE );
                message->setNonce(3);
                param = this->cipherDH->generatePartialKey();
                this->cipherDH->stash();
                message->set_DH_key( param->getMessage(), param->length() );
                this->cipher2->sign( message );
                break;

            case utility::USER_LIST_REQ:
                message->setMessageType( USER_LIST_REQ );
                message->setNonce(4);
                this->cipher2->sign( message );
                break;

            case utility::RANK_LIST_REQ:
                message->setMessageType( RANK_LIST_REQ );
                message->setNonce(5);
                this->cipher2->sign( message );
                break;

            case utility::LOGOUT_REQ:
                message->setMessageType( LOGOUT_REQ );
                message->setNonce(6);
                this->cipher2->sign( message );
                break;
        }

    return message;
}
void PowerClient::showMessage(Message* message){

    unsigned char* result;

    switch( message->getMessageType() ){
        case utility::CERTIFICATE:
            cout<<"------ CERTIFICATE ------"<<endl<<endl;
            cout<<"\t- NONCE: "<<*(message->getNonce())<<endl;
            this->nonce = *(message->getNonce())+1;
            cout<<"\tCERTIFICATE:"<<endl;
            result = message->getServerCertificate();
            for( int a= 0; a<message->getServerCertificateLength(); a++ )
                cout<<result[a];
            cout<<endl<<endl;
            cout<<"-------------------"<<endl<<endl;
            break;

        case utility::LOGIN_OK:
            cout<<"------ LOGIN_OK ------"<<endl<<endl;
            cout<<"\t- NONCE: "<<*(message->getNonce())<<endl<<endl;
            cout<<"-------------------"<<endl<<endl;
            break;

        case utility::LOGIN_FAIL:
            cout<<"------ LOGIN_FAIL ------"<<endl<<endl;
            cout<<"\t- NONCE: "<<*(message->getNonce())<<endl<<endl;
            cout<<"-------------------"<<endl<<endl;
            break;

        case utility::KEY_EXCHANGE:
            cout<<"------ KEY_EXCHANGE ------"<<endl<<endl;
            cout<<"\t- NONCE: "<<*(message->getNonce())<<endl<<endl;
            result = message->getDHkey();
            for( int a= 0; a<message->getDHkeyLength(); a++ )
                cout<<result[a];
            cout<<endl<<endl;
            this->cipherAes->modifyParam( this->cipherDH->generateSessionKey( result , message->getDHkeyLength()) );
            cout<<"-------------------"<<endl<<endl;
            break;

        case utility::USER_LIST:
            cout<<"------ USER_LIST ------"<<endl<<endl;

            message = this->cipherAes->decryptMessage(*message);
            cout<<"\t- NONCE: "<<*(message->getNonce())<<endl<<endl;
            result = message->getUserList();
            for( int a= 0; a<message->getUserListLen(); a++ )
                cout<<result[a];
            cout<<endl<<endl;
            cout<<"-------------------"<<endl<<endl;
            break;

        case utility::RANK_LIST:
            cout<<"------ RANK_LIST ------"<<endl<<endl;
            message = this->cipherAes->decryptMessage(*message);
            cout<<"\t- NONCE: "<<*(message->getNonce())<<endl<<endl;
            result = message->getRankList();
            for( int a= 0; a<message->getRankListLen(); a++ )
                cout<<result[a];
            cout<<endl<<endl;
            cout<<"-------------------"<<endl<<endl;
            break;

        case utility::LOGOUT_OK:
            cout<<"------ LOGOUT_OK ------"<<endl<<endl;
            message = this->cipherAes->decryptMessage(*message);
            cout<<"\t- NONCE: "<<*(message->getNonce())<<endl<<endl;
            cout<<"-------------------"<<endl<<endl;
            break;

        case utility::ERROR:
            cout<<"------ ERROR ------"<<endl<<endl;
            cout<<"\t- NONCE: "<<*(message->getNonce())<<endl<<endl;
            result = message->getMessage();
            for( int a= 0; a<message->getMessageLength(); a++ )
                cout<<result[a];
            cout<<endl<<endl;
            cout<<"-------------------"<<endl<<endl;
            break;
    }
}

int main(){

    Logger::setThreshold(NO_VERBOSE);
    PowerClient* client = new PowerClient(string("127.0.0.1"),12345);
    cout<<"--------------------start"<<endl;
   // client->sendMessage(USER_LIST_REQ,true);
   // client->sendMessage(RANK_LIST_REQ,true);
   // client->sendMessage(KEY_EXCHANGE,true);
   // client->sendMessage(LOGOUT_REQ,true);
    client->sendMessage(CERTIFICATE_REQ,true);
    client->sendMessage(LOGIN_REQ,true);
    client->sendMessage(KEY_EXCHANGE,true);
    client->sendMessage(USER_LIST_REQ,true);
    client->sendMessage(RANK_LIST_REQ,true);
    client->sendMessage(LOGOUT_REQ,true);
  //  client->sendMessage(USER_LIST_REQ,true);
    delete client;
}
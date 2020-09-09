
#include "PowerClient.h"

PowerClient::PowerClient( string ipAddr, int port ){

    this->cipher = nullptr;
    this->cipherDH = new cipher::CipherDH();
    this->cipherAes = new cipher::CipherAES();
    this->manager = new ConnectionManager(false,ipAddr.c_str(),port);
    this->port = port;

    if(!this->manager->createConnectionWithServerTCP( ipAddr.c_str(), 12345 )){

        std::cout<<"connection not created"<<endl;
        exit(1);

    }
    this->server_socket = this->manager->getserverSocket();

}

void PowerClient::sendMessage( MessageType type, const char* param ){

    bool okSend;
    const char *m = nullptr;
    string *s;
    int idSock;
    vector<int> vect;

    Message* message = this->createMessage( type, param );

    this->manager->sendMessage( *message, this->server_socket, &okSend, m, 0 );

}

void PowerClient::waitMessage(){
    int idSock;
    string *s;
    vector<int> vect = this->manager->waitForMessage( &idSock ,s );
    Message* message;

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

Message* PowerClient::createMessage( MessageType type, const char* param ){

    Message* message = new Message();
    string password;
    NetMessage* mParam;
    NetMessage* net;
    switch( type ){
            case utility::CERTIFICATE_REQ:
                message->setMessageType( CERTIFICATE_REQ );
                message->setNonce(0);
                break;

            case utility::LOGIN_REQ:
                message->setMessageType( LOGIN_REQ );
                message->setNonce(this->nonce);
                message->setPort( this->port );
                this->username = string(param);
                password = this->username;
                password.append( "Password" );

                this->cipher = new cipher::CipherRSA( this->username, password, false );

                message->setUsername(param );
                this->cipher->sign( message );
                this->nonce++;
                break;

            case utility::KEY_EXCHANGE:

                message->setMessageType( KEY_EXCHANGE );
                message->setNonce(this->nonce);
                mParam = this->cipherDH->generatePartialKey();
                message->set_DH_key( mParam->getMessage(), mParam->length() );
                this->cipher->sign( message );
                this->nonce++;
                break;

            case utility::USER_LIST_REQ:
                message->setMessageType( USER_LIST_REQ );
                message->setNonce(this->nonce);
                message = this->cipherAes->encryptMessage(*message);
                this->nonce++;
                break;

            case utility::RANK_LIST_REQ:
                message->setMessageType( RANK_LIST_REQ );
                message->setNonce(this->nonce);
                message = this->cipherAes->encryptMessage(*message);
                this->nonce++;
                break;

            case utility::LOGOUT_REQ:
                message->setMessageType( LOGOUT_REQ );
                message->setNonce(this->nonce);
                message = this->cipherAes->encryptMessage(*message);
                this->nonce++;
                break;
            case utility::ACCEPT:
                message->setMessageType( ACCEPT );
                message->setNonce(this->nonce);
                message->setAdversary_1( param );
                message->setAdversary_2(this->username.c_str());
                message = this->cipherAes->encryptMessage(*message);
                this->nonce++;
                break;
            case utility::REJECT:
                message->setMessageType( REJECT );
                message->setNonce(this->nonce);
                message->setAdversary_1(param );
                message->setAdversary_2(this->username.c_str());
                message = this->cipherAes->encryptMessage(*message);
                this->nonce++;
                break;
            case utility::WITHDRAW_REQ:
                message->setMessageType( WITHDRAW_REQ );
                message->setNonce(this->nonce);
                message->setUsername(this->username);
                message = this->cipherAes->encryptMessage(*message);
                this->nonce++;
                break;
            case utility::MATCH:
                message->setMessageType( MATCH );
                message->setNonce(this->nonce);
                message->setUsername(string(param) );
                message = this->cipherAes->encryptMessage(*message);
                net = Converter::encodeMessage(MATCH, *message );
                message = this->cipherAes->encryptMessage(*message);
                this->nonce++;
                break;
            case utility::DISCONNECT:
                message->setMessageType( DISCONNECT );
                message->setNonce(this->nonce);
                message->setUsername(string(param) );
                message = this->cipherAes->encryptMessage(*message);
                net = Converter::encodeMessage(MATCH, *message );
                message = this->cipherAes->encryptMessage(*message);
                this->nonce++;
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
        case utility::MATCH:
            cout<<"------ MATCH ------"<<endl<<endl;
            cout<<"\t- NONCE: "<<*(message->getNonce())<<endl<<endl;
            cout<<"\t- USER: "<<message->getUsername()<<endl<<endl;
            cout<<"-------------------"<<endl<<endl;
            break;
        case utility::ACCEPT:
            cout<<"------ ACCEPT ------"<<endl<<endl;
            cout<<"\t- NONCE: "<<*(message->getNonce())<<endl<<endl;
            cout<<"\t- CHALLENGER: "<<message->getAdversary_1()<<endl<<endl;
            cout<<"\t- CHALLENGED: "<<message->getAdversary_2()<<endl<<endl;
            cout<<"-------------------"<<endl<<endl;
            break;
        case utility::REJECT:
            cout<<"------ REJECT ------"<<endl<<endl;
            cout<<"\t- NONCE: "<<*(message->getNonce())<<endl<<endl;
            cout<<"\t- CHALLENGER: "<<message->getAdversary_1()<<endl<<endl;
            cout<<"\t- CHALLENGED: "<<message->getAdversary_2()<<endl<<endl;
            cout<<"-------------------"<<endl<<endl;
            break;
        case utility::DISCONNECT:
            cout<<"------ DISCONNECT ------"<<endl<<endl;
            cout<<"\t- NONCE: "<<*(message->getNonce())<<endl<<endl;
            cout<<"-------------------"<<endl<<endl;
            break;
        case utility::WITHDRAW_OK:
            cout<<"------ ACCEPT ------"<<endl<<endl;
            cout<<"\t- NONCE: "<<*(message->getNonce())<<endl<<endl;
            cout<<"\t- CHALLENGER: "<<message->getUsername()<<endl<<endl;
            cout<<"-------------------"<<endl<<endl;
            break;
        case utility::GAME_PARAM:
            cout<<"------ ACCEPT ------"<<endl<<endl;
            cout<<"\t- NONCE: "<<*(message->getNonce())<<endl<<endl;
            cout<<"\t- IP: "<<message->getNetInformations()<<endl<<endl;
            cout<<"\t- PUBKEY: ";
            result = message->getPubKey();
            for( int a= 0; a<message->getPubKeyLength(); a++ )
                cout<<result[a];
            cout<<endl<<endl;
            cout<<"-------------------"<<endl<<endl;
            break;
        default:
            cout<<"Message unknown"<<'\n';
    }
}

void PowerClient::startClient() {
    int choose;
    string param;
    while(true){
        cout<<"0) WAIT"<<'\n'<<"1) CERTIFICATE_REQ"<<'\n'<<"2) LOGIN_REQ"<<'\n'<<"3) KEY_EXCHANGE"<<'\n'<<"4) USER_REQ"<<'\n'<<"5) RANK_REQ"<<'\n'<<"6)MATCH"<<'\n'<<"7)ACCEPT"<<'\n'<<"8) REJECT"<<'\n'<<"9)WITHDRAW"<<'\n'<<"10)DISCONNECT"<<'\n'<<"11)LOGOUT"<<'\n'<<endl;
        cout<<"Choose the message to send: "<<'\n';
        cin>>choose;
        switch(choose){
            case 0: this->waitMessage();
                    break;
            case 1: this->sendMessage( CERTIFICATE_REQ, "" );
                    break;
            case 2: cout<<"Insert a username: ";
                    cout.flush();
                    cin>>param;
                    this->sendMessage( LOGIN_REQ, param.c_str() );
                    break;
            case 3: this->sendMessage(KEY_EXCHANGE, "" );
                    break;
            case 4: this->sendMessage( USER_LIST_REQ, "" );
                    break;
            case 5: this->sendMessage( RANK_LIST_REQ, "" );
                    break;
            case 6: cout<<"Insert a username: ";
                    cout.flush();
                    cin>>param;
                    this->sendMessage( MATCH, param.c_str());
                    break;
            case 7:  cout<<"Insert a username: ";
                    cout.flush();
                    cin>>param;
                    this->sendMessage( ACCEPT, param.c_str());
                    break;
            case 8: cout<<"Insert a username: ";
                    cout.flush();
                    cin>>param;
                    this->sendMessage( REJECT, param.c_str());
                    break;
            case 9: this->sendMessage( WITHDRAW_REQ, "" );
                    break;
            case 10:this->sendMessage( DISCONNECT, "" );
                    break;
            case 11:this->sendMessage( LOGOUT_REQ, "" );
                    break;

        }
    }


}


int main( int argc, char* argv[] ) {

    if( argc<1){
        cout<<"Inserire socket udp"<<'\n';
        return 1;
    }
    Logger::setThreshold(NO_VERBOSE);
    PowerClient *client;

    client = new PowerClient(string("127.0.0.1"), atoi(argv[1]));

    client->startClient();
}
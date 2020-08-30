#include"utility/Message.h"
#include<vector>
#include<stdexcept>
#include"Logger.h"
#include"utility/ConnectionManager.h"
#include "cipher/CipherRSA.h"
#include "cipher/CipherDH.h"
#include"utility/NetMessage.h"
#include<stdlib.h>
#include<iostream>
using namespace utility;

void sendMessage( MessageType type , bool correctness ){

    switch( type ){

        case utility::CERTIFICATE_REQ:
        case utility::LOGIN_REQ:
        case utility::KEY_EXCHANGE:
        case utility::USER_LIST_REQ:
        case utility::RANK_LIST_REQ:

    }
}
int main()
{
    cipher::CipherRSA* cipherRSA = new cipher::CipherRSA( "bob", "bobPassword", false );

    Logger::setThreshold( NO_VERBOSE );

    vector<int> vect;
    const char* IP="127.0.0.1";
    int port= 12345;
    int idsock;
    unsigned char* res;
    bool result;
    Message* retMsg;
    ConnectionManager connectionManager(false,IP,port);

    bool connect=connectionManager.createConnectionWithServerTCP("127.0.0.1",12345);
    if(!connect){

        std::cout<<"connection not created"<<endl;
        return 1;

    }

    string *s;
    Message* m;

    int sock_serv=connectionManager.getserverSocket();

    m = new Message();
    const char *m1=nullptr;
    m->setNonce( 1 );
    m->setMessageType( CERTIFICATE_REQ );
    bool okSend;
    result=connectionManager.sendMessage(*m,sock_serv,&okSend, m1,0);
    std::cout<<"result: "<<result<<endl;
    vect=connectionManager.waitForMessage(&idsock,s);

    if( vect.size()){
        for( int sock: vect ) {
            retMsg = connectionManager.getMessage(sock);
            cout << "Received message: " << endl;
            cout << "MessageType: " << retMsg->getMessageType() << endl;
            cout << "Nonce: " << *(retMsg->getNonce()) << endl;
            cout << "Certificate: " << endl;
            res = retMsg->getServerCertificate();
            for (int a = 0; a < retMsg->getServerCertificateLength(); a++)
                cout << res[a];
            cout << endl;
        }
    }
    vect.clear();
    delete m;

    m = new Message();
    const char *m2=nullptr;
    m->setNonce( 2 );
    m->setUsername("bob");
    m->setMessageType(LOGIN_REQ );
    cipherRSA->sign( m );
    result=connectionManager.sendMessage(*m,sock_serv,&okSend, m2,0);
    std::cout<<"result: "<<result<<endl;
    vect=connectionManager.waitForMessage(&idsock,s);

    if( vect.size()){
        for( int sock: vect ) {
            retMsg = connectionManager.getMessage(sock);
            cout << "Received message: " << endl;
            cout << "MessageType: " << retMsg->getMessageType() << endl;
            cout << "Nonce: " << *(retMsg->getNonce()) << endl;
        }
    }
    vect.clear();
    delete m;

    cipher::CipherDH* dh = new cipher::CipherDH();
    NetMessage* param = dh->generatePartialKey();
    m = new Message();
    const char *m6=nullptr;
    m->setNonce( 2 );
    m->setMessageType(KEY_EXCHANGE );
    m->set_DH_key( param->getMessage(), param->length() );
    cipherRSA->sign( m );

    result=connectionManager.sendMessage(*m,sock_serv,&okSend, m6,0);
    std::cout<<"result: "<<result<<endl;
    vect=connectionManager.waitForMessage(&idsock,s);

    if( vect.size()){
        for( int sock: vect ) {
            retMsg = connectionManager.getMessage(sock);
            cout << "Received message: " << endl;
            cout << "MessageType: " << retMsg->getMessageType() << endl;
            cout << "Nonce: " << *(retMsg->getNonce()) << endl;
        }
    }
    vect.clear();
    delete m;

    m = new Message();
    const char *m3=nullptr;
    m->setNonce( 10);
    m->setMessageType(USER_LIST_REQ );
    cipherRSA->sign( m );

    result=connectionManager.sendMessage(*m,sock_serv,&okSend, m3,0);
    std::cout<<"result: "<<result<<endl;
    vect=connectionManager.waitForMessage(&idsock,s);
    cout<<"okokokok"<<endl;
    if( vect.size()){
        for( int sock: vect ) {
            retMsg = connectionManager.getMessage(sock);
            cout << "Received message: " << endl;
            cout << "MessageType: " << retMsg->getMessageType() << endl;
            cout << "Nonce: " << *(retMsg->getNonce()) << endl;
            cout<<"User_list: "<<endl;
            res = retMsg->getUserList();
            for (int a = 0; a < retMsg->getUserListLen(); a++)
                cout << res[a];
            cout << endl;
        }
    }
    vect.clear();
    delete m;


    m = new Message();
    const char *m4=nullptr;
    m->setNonce( 4 );
    m->setMessageType(RANK_LIST_REQ);
    cipherRSA->sign( m );

    result=connectionManager.sendMessage(*m,sock_serv,&okSend, m4,0);
    std::cout<<"result: "<<result<<endl;
    vect=connectionManager.waitForMessage(&idsock,s);

    if( vect.size()){
        for( int sock: vect ) {
            retMsg = connectionManager.getMessage(sock);
            cout << "Received message: " << endl;
            cout << "MessageType: " << retMsg->getMessageType() << endl;
            cout << "Nonce: " << *(retMsg->getNonce()) << endl;
            cout<<"User_list: "<<endl;
            res = retMsg->getRankList();
            for (int a = 0; a < retMsg->getRankListLen(); a++)
                cout << res[a];
            cout << endl;
        }
    }
    vect.clear();
    delete m;

    m = new Message();
    const char *m5=nullptr;
    m->setNonce( 5 );
    m->setMessageType(LOGOUT_REQ );
    cipherRSA->sign( m );

    result=connectionManager.sendMessage(*m,sock_serv,&okSend, m5,0);
    std::cout<<"result: "<<result<<endl;
    vect=connectionManager.waitForMessage(&idsock,s);

    if( vect.size()){
        for( int sock: vect ) {
            retMsg = connectionManager.getMessage(sock);
            cout << "Received message: " << endl;
            cout << "MessageType: " << retMsg->getMessageType() << endl;
            cout << "Nonce: " << *(retMsg->getNonce()) << endl;
        }
    }
    vect.clear();
    delete m;

}
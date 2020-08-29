#include"utility/Message.h"
#include<vector>
#include<stdexcept>
#include"Logger.h"
#include"utility/ConnectionManager.h"
#include "cipher/CipherRSA.h"
#include"utility/NetMessage.h"
#include<stdlib.h>
#include<iostream>
using namespace utility;
int main()
{
    cipher::CipherRSA* cipherRSA = new cipher::CipherRSA( "bob", "bobPassword", false );

    vector<int> vect;
    const char* IP="127.0.0.1";
    int port= 12345;
    int idsock;
    unsigned char* res;
    bool result;
    Message* retMsg;
    ConnectionManager connectionManager(false,IP,port);
    bool connect=connectionManager.createConnectionWithServerTCP("127.0.0.1",12345);
    if(!connect)
    {
        std::cout<<"connection not create"<<endl;
    }

    string *s;
    Message* m;

    int sock_serv=connectionManager.getserverSocket();


    m = new Message();
    const char *m1=nullptr;
    m->setNonce( 1 );
    m->setMessageType(CERTIFICATE_REQ);

    result=connectionManager.sendMessage(*m,sock_serv,m1,0);
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

    result=connectionManager.sendMessage(*m,sock_serv,m2,0);
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
    m->setNonce( 3);
    m->setMessageType(USER_LIST_REQ );
    cipherRSA->sign( m );

    result=connectionManager.sendMessage(*m,sock_serv,m3,0);
    std::cout<<"result: "<<result<<endl;
    vect=connectionManager.waitForMessage(&idsock,s);

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

    result=connectionManager.sendMessage(*m,sock_serv,m4,0);
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



}
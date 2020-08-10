#include "NetMessage.h"

namespace utility {

    NetMessage::NetMessage(unsigned char *message, int length) {
        vverbose<<"-->[NetMessage][Costructor] Generation of message: "<<message<<'\n';
        this->message = new unsigned char[length];
        strcpy((char*)this->message,(const char*)message);
        this->len = length;
        vverbose<<"-->[NetMessage][Costructor] Message generated"<<'\n';

    }

    NetMessage::~NetMessage(){
   //     delete[] message;
    }

    unsigned char* NetMessage::getMessage(){
        return this->message;
    }

    int NetMessage::length(){
        return this->len;
    }

    void NetMessage::test(){

        NetMessage msg((unsigned char*)"messaggio di prova" , sizeof("messaggio di prova" ));
        cout<<"CONTENT: " << msg.getMessage()<<" LENGTH: "<<msg.length()<<endl;

    }

}
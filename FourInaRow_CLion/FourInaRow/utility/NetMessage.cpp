

#include <ostream>
#include <cstring>
#include "NetMessage.h"
#include "../Logger.h"

namespace utility {

    NetMessage::NetMessage(unsigned char *message, int length) {

        this->message = message;
        this->len = length;

    }

    unsigned char* NetMessage::getMessage(){
        return this->message;
    }

    int NetMessage::length(){
        return this->len;
    }

    void NetMessage::test(){

        NetMessage msg((unsigned char*)"messaggio di prova" , sizeof("ciao ciao" ));
        cout<<"CONTENT: " << msg.getMessage()<<" LENGTH: "<<msg.length()<<endl;

    }

}

#include <iostream>
#include "cipher/CipherRSA.h"
#include "Logger.h"
#include "utility/Message.h"
#include "utility/NetMessage.h"
#include "utility/Converter.h"
using namespace cipher;

    int main() {
        Logger::setThreshold( VERBOSE );
        utility::Message* msg = new utility::Message();
        msg->setNonce(10);
        utility::NetMessage *net = utility::Converter::encodeMessage(utility::WITHDRAW_OK,*msg);
        cout<<"------------------------------ "<<net->getMessage()<<endl;
        
        CipherRSA rsa( "bob" , "bobPassword");
        delete msg;
        delete net;
        return 0;
    }




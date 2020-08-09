#include <iostream>
#include "utility/NetMessage.h"
#include "Logger.h"
#include "utility/Message.h"
#include "utility/Converter.h"

using namespace utility;

    int main() {
        Logger::setThreshold( VERY_VERBOSE );
        base<<"ciao"<<'\n';
        verbose<<"ciao"<<'\n';
        vverbose<<"ciao"<<'\n';

        Message* msg = new Message();
        msg->setNonce(10);
        NetMessage* net = Converter::encodeMessage(WITHDRAW_OK , *msg );
        if( net != NULL )
            base << net->getMessage() <<'\n';
        delete msg;


        return 0;
    }




#include <iostream>
#include "cipher/CipherRSA.h"
#include "Logger.h"
#include "utility/Message.h"
#include "utility/NetMessage.h"
#include "utility/Converter.h"
using namespace utility;
    int main() {

        Logger::setThreshold( VERY_VERBOSE );
        base<<"------------------------------------------------------------"<<"\n\n";
        Converter::test();
/*        Message *msg = new Message();
        msg->setNonce(10);
        msg->setMessageType(WITHDRAW_OK);
        msg->setUsername("fava");
        CipherRSA rsa( "bob" , "bobPassword");
        verbose<<*msg<<'\n';
        rsa.sign(msg);
       // cout<<msg->getSignatureLen()<<endl;
       // verbose<<*msg<<'\n';
      //  cout<<rsa.clientVerifySignature(*msg,true)<<endl;
      //  cout<<rsa.serverVerifySignature(*msg,"bob")<<endl;*/
      //  delete msg;

        return 0;
    }




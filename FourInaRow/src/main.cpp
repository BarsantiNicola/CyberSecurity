#include <iostream>
#include "cipher/CipherRSA.h"
#include "Logger.h"
#include "utility/Message.h"
#include "utility/NetMessage.h"
#include "utility/Converter.h"
#include "cipher/CipherDH.h"
#include "server/SQLConnector.h"
using namespace utility;



    int main() {

        Logger::setThreshold( VERY_VERBOSE );
        base<<"------------------------------------------------------------"<<"\n\n";
        server::SQLConnector::incrementUserGame("ale",true);
        server::SQLConnector::incrementUserGame("ale",false);
        server::SQLConnector::incrementUserGame("ale",false);

        cout<<server::SQLConnector::getRankList()<<endl;
     //   Converter::test();
      //  cipher::CipherRSA::test();
      //cipher::CipherDH::test();

        return 0;
    }




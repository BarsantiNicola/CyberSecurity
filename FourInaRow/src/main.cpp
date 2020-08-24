#include <iostream>
#include "cipher/CipherRSA.h"
#include "Logger.h"
#include "utility/Message.h"
#include "utility/NetMessage.h"
#include "utility/Converter.h"
#include "cipher/CipherDH.h"
#include "server/SQLConnector.h"
#include "utility/Register.h"
#include "server/ClientInformation.h"

using namespace utility;



    int main() {

        Logger::setThreshold( VERY_VERBOSE );
        base<<"------------------------------------------------------------"<<"\n\n";
     //   server::SQLConnector::incrementUserGame("ale",server::WIN);
     //   server::SQLConnector::incrementUserGame("ale",server::LOOSE);
     //   server::SQLConnector::incrementUserGame("ale",server::TIE);

     //   cout<<server::SQLConnector::getRankList()<<endl;
       Register<server::ClientInformation> *prova = new Register<server::ClientInformation>();
       delete prova;
     //   Converter::test();
      //  cipher::CipherRSA::test();
      //cipher::CipherDH::test();

        return 0;
    }




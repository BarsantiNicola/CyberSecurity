#include <iostream>
#include "cipher/CipherRSA.h"
#include "Logger.h"
#include "utility/Message.h"
#include "utility/NetMessage.h"
#include "utility/Converter.h"
#include "cipher/CipherDH.h"
using namespace utility;



    int main() {

        Logger::setThreshold( VERY_VERBOSE );
        base<<"------------------------------------------------------------"<<"\n\n";

     //   Converter::test();
      //  cipher::CipherRSA::test();
      cipher::CipherDH::test();

        return 0;
    }




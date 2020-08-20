#include <iostream>
#include "cipher/CipherRSA.h"
#include "Logger.h"
#include "utility/Message.h"
#include "utility/NetMessage.h"
#include "utility/Converter.h"
using namespace utility;



    int main() {

        Logger::setThreshold( VERBOSE );
        base<<"------------------------------------------------------------"<<"\n\n";

     //   Converter::test();
        cipher::CipherRSA::test();

        return 0;
    }




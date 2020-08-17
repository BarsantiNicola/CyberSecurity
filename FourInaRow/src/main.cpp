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
        //cipher::CipherRSA::test();
        Converter::test();
        return 0;
    }




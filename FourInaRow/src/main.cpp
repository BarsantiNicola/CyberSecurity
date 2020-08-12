#include <iostream>
#include "cipher/CipherRSA.h"
#include "Logger.h"
#include "utility/Message.h"
#include "utility/NetMessage.h"
#include "utility/Converter.h"
using namespace cipher;

    int main() {

        Logger::setThreshold( VERY_VERBOSE );
        base<<"------------------------------------------------------------"<<"\n\n";
        CipherRSA rsa( "bob" , "bobPassword");

        return 0;
    }




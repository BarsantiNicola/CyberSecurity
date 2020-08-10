#include <iostream>
#include "utility/NetMessage.h"
#include "Logger.h"
#include "utility/Message.h"
#include "utility/Converter.h"

using namespace utility;

    int main() {
        Logger::setThreshold( VERBOSE );
        base<<Converter::test()<<'\n';
        return 0;
    }




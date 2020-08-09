//
// Created by root on 09/08/20.
//

#ifndef FOURINAROW_CONVERTER_H
#define FOURINAROW_CONVERTER_H
#include "NetMessage.h"
#include "Message.h"
namespace utility{


class Converter {
    private:
        static bool verifyMessage( MessageType type , Message message );
    public:
        static NetMessage* encodeMessage(MessageType type , Message message );
        static Message* decodeMessage( NetMessage message );
};

}
#endif //FOURINAROW_CONVERTER_H

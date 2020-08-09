

#ifndef FOURINAROW_NETMESSAGE_H
#define FOURINAROW_NETMESSAGE_H

namespace utility{

    class NetMessage {
        private:
            unsigned char* message;
            int len;
        public:
            NetMessage(unsigned char* message , int length );
            unsigned char* getMessage();
            int length();
            static void test();

    };

}
#endif //FOURINAROW_NETMESSAGE_H

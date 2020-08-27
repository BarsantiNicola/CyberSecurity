
#ifndef FOURINAROW_CLIENTINFORMATION_H
#define FOURINAROW_CLIENTINFORMATION_H

#include <iostream>

using namespace std;

namespace server {

class ClientInformation{

        private:

            string IPaddress;
            int socket;

        public:
            ClientInformation( string IPaddress, int socket );

            string getIPaddress();
            int getSocket();


    };

}

#endif //FOURINAROW_CLIENTINFORMATION_H

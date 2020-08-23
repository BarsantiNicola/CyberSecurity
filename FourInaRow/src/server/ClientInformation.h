
#ifndef FOURINAROW_CLIENTINFORMATION_H
#define FOURINAROW_CLIENTINFORMATION_H

#include <iostream>
using namespace std;

namespace server {

    class ClientInformation {

        private:
            int clientID;
            string IPaddress;
            int socket;

        public:
            ClientInformation(int clientID, string IPaddress, int socket);
            int getClientID();
            string getIPaddress();
            int getSocket();

    };

}

#endif //FOURINAROW_CLIENTINFORMATION_H

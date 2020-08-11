#include<stdexcept>
#include<unistd.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include "NetMessage.h"
#include "Message.h"
#include <iostream>
#include<string>
#include "Converter.h"
#include "../Logger.h"
using namespace std;
namespace utility
{
  class ConnectionManager
  {
    private:
      int listener;
      int serverSocket=-2;
      int socketUDP=-2;
      int standardIO;
      int fdmax;
      bool isServer;
      fd_set master;
      fd_set fdRead;
      Message message;
      struct sockaddr_in my_addr;
      struct sockaddr_in server_addr;
      //vector<sockaddr_in> clients_addr;
    public:
      ConnectionManager(bool,const char*,int);
      bool createConnectionWithServerTCP(const char*,int);
      bool registerConnection();
      Message getMessage(int); 
      bool removeConnection(int);
      bool sendMessage(int,Message);
      int waitForMessage();
    private:
      bool createListenerTcp();
      bool resendMessage();
      int udpBind(int);//da verificare se necessaria
      int tcpBind(int);
  };

}

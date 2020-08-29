#include<exception>
#include<unistd.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include "NetMessage.h"
#include "Message.h"
#include <iostream>
#include<vector>
#include<string>
#include "Converter.h"
#include "../Logger.h"

#define BUFFER_LENGTH 32000
using namespace std;
namespace utility
{
  class ConnectionManager
  {
    private:
      int listener=-2;
      int serverSocket=-2;
      int socketUDP=-2;
      int standardIO;
      int fdmax=0;
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
      //bool registerConnection();
      Message* getMessage(int); 
      bool closeConnection(int);
      bool sendMessage(Message,int,bool*,const char*,int);
      vector<int> waitForMessage(int*,string*);
      int getsocketUDP();
      int getserverSocket();
    private:
      void copyBuffer(unsigned char*,unsigned char*,int,int);
      void initArray(unsigned char*,unsigned char,int);
      bool createListenerTcp();
      int ReturnIndexLastSimbolPosition(unsigned char*,int,unsigned char);
      bool resendMessage();
      //int udpBind(int);//da verificare se necessaria
      //int tcpBind(int);
  };

}

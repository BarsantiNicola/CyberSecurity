#include"ConnectionManager.h"
namespace utility
{
  ConnectionManager::ConnectionManager(bool isServer,const char* myIP,int myPort)
  { 
    
    
    int ret;
    bool ris;
    FD_ZERO(&master);
    FD_ZERO(&fdRead);
    FD_SET(fileno(stdin),&master);
    fd_max=fileno(stdin);
    memset(&my_addr,0,sizeof(my_addr));
    my_addr.sin_family=AF_INET;
    my_addr.sin_port=htons(myPort);
    this->isServer=isServer;
    ret=inet_pton(AF_INET,myIP,&my_addr.sin_addr);
    if(ret==-1)
    {
      verbose<<"-->[ConnectionManager][Costructor] Error invalid IP address exit"<<'\n';
      exit(-1);
    }
    if(isServer)
    {
      ris=createListenerTcp();
      if(!ris)
      {
        verbose<<"-->[ConnectionManager][Costructor] Error to creating a ListenerTCP exit"<<'\n';
        exit(-1);     
       }

      else
        vverbose<<"-->[ConnectionManager][Costructor] Connection manager Object was created succesfully"<<'\n';
    }
    else
    {
      socketUDP=socket(AF_INET,SOCK_DGRAM,0);
      if(socketUDP==-1)
        exit(-1);
    }
    ret=bind(socketUDP,(struct sockaddr*) &my_addr,sizeof(my_addr));
    if(ret==-1)
    {
       verbose<<"-->[ConnectionManager][Costructor] Error to UDP bind exit"<<'\n';
       exit(-1);     
    }
    FD_SET(socketUDP,&master);
    if(fdmax<socketUDP)
     {
       fdmax=socketUDP;
     }  
  }



  bool ConnectionManager::createListenerTcp()
  {
    int ret;
    if (!isServer||listener!=-2)
      return false;
    listener = socket(AF_INET,SOCK_STREAM,0);
    if(listener==-1)
      return false;
    ret= bind(listener,(struct sockaddr*)& my_addr,sizeof(my_addr));
    if(ret==-1)
      return false;//exit(-1);
    listen(listener,150);
    FD_SET(listener,&master);
    fdmax=listener;
    return true;
    
  }



  bool ConnectionManager::createConnectionWithServer(const char* IP,int port)
  {
     int ret;
     if(isServer)
     {
       verbose<<"-->[ConnectionManager][createConnectionWithServer] Error can't create a connection between two servers, return false"<<'\n';
       return false;
     }
    memset(&my_addr,0,sizeof(server_addr));
    server_addr.sin_family=AF_INET;
    server_addr.sin_port=htons(port);
    ret=inet_pton(AF_INET,myIP,&my_addr.sin_addr);
    if(ret==-1)
    {
      throw invalid_argument("Invalid IP address");
    }
    serverSocket=socket(AF_INET,SOCK_STREAM,0);
    inet_pton(AF_INET)
    ret= connect(serverSocket,(struct sockaddr*)&server_addr,sizeof(server_addr));
    if(ret==-1)
    {
      verbose<<"-->[ConnectionManager][createConnectionWithServer] Error connection, return false"<<'\n';
      return false;
    }
    vverbose<<"-->[ConnectionManager][createConnectionWithServer] the connection with server was created succesfully idsock:"<<serverSocket<<'\n';
    FD_SET(serverSocket,&master);
    if(serverSocket>fdmax)
      fdmax=serverSocket;
    return true;
  }

  bool ConnectionManager::sendMessage(Message message,int socket,const char recIP,int recPort)
  {  
    int ret;
    uint16_t lmsg;
    Converter* conv=new Converter();
    if(message.length()>BUFFER_LENGTH)
    {
      verbose<<"-->[ConnectionManager][sendMessage] Error Message to long"<<'\n';
      return false;
      }   
    if((isServer&&FD_ISSET(socket,&master))||(!isServer&&serverSocket==socket&&serverSocket!=-2))
    {
      NetMessage* netmess=conv->encodeMessage(message.getMessageType(),message );
      if(netmess==NULL)
      {
        verbose<<"-->[ConnectionManager][sendMessage] Error conversion"<<'\n';
        return false;
      }
      /*lmsg=htons(netmess->length());
      ret=send(socket,(void*)&lmsg,sizeof(uint16_t),0);
      if(ret==0)
      {
        verbose<<"-->[ConnectionManager][sendMessage] connection closed"<<'\n';
        return false;
      }
      if(ret<sizeof(uint16_t))
      {
        verbose<<"-->[ConnectionManager][sendMessage] send message length failed"<<'\n';
        return false;
      }*/
      ret=send(socket,(void*)netmess->getMessage());
      if(ret==0)
      {
        verbose<<"-->[ConnectionManager][sendMessage] connection closed"<<'\n';
        return false;
      }
      if(ret<netmess->length())
      {
        verbose<<"-->[ConnectionManager][sendMessage] send message failed"<<'\n';
        return false;
      }
      return true;
    }
    else if(socketUDP==socket)
    {
      struct sockaddr reciver_addr;
      memset(&reciver_addr,0,sizeof(reciver_addr));
      reciver_addr.sin_family=AF_INET;
      reciver_addr.sin_port=htons(recPort);
      ret=inet_pton(AF_INET,recIP,&reciver_addr.sin_addr);
      if(ret==-1)
      {
        verbose<<"-->[ConnectionManager][sendMessage] bad reciver address "<<'\n';
        return false;
      }
      NetMessage* netmess=conv->encodeMessage(message.getMessageType(),message );
      if(netmess==NULL)
      {
        verbose<<"-->[ConnectionManager][sendMessage] Error conversion"<<'\n';
        return false;
      }
      /*lmsg=htons(netmess->length());
      ret=sendto(socket,(void*)&lmsg,sizeof(uint16_t),0,(struct sockaddr*)&reciver_addr,sizeof(reciver_addr));
      if(ret<sizeof(uint16_t))
      {
        verbose<<"-->[ConnectionManager][sendMessage] send message length failed"<<'\n';
        return false;
      }*/
      ret=sendto(sock,netmess->getMessage(),&netmess->length(),0,(struct sockaddr*) &reciver_addr, sizeof(reciver_addr));
      if(ret==0)
      {
        verbose<<"-->[ConnectionManager][sendMessage] connection closed"<<'\n';
        return false;
      }
      if(ret<netmess->length())
      {
        verbose<<"-->[ConnectionManager][sendMessage] send message failed"<<'\n';
        return false;
      }
      return true;
    }
  }
 
  bool ConnectionManager::removeConnection(int socket)
  {
    int ret= close(socket);
    if(ret==0)
    {
      if(FD_ISSET(socket,&master))
        FD_CLR(socket,&master);
         
      return true;
      
    }
    return false;
  }
  //funzione che restituisce un vector di id di socket pronti in caso non ci siano descrittori pronti restituisce un vector vuoto
  vector<int> ConnectionManager::waitForMessage()
  {
    vector<int> descr;
    fdRead=master;
    select(fdmax+1,&fdRead,NULL,NULL,NULL);
    for(i=0;i<=fdmax;i++)
    {
      if(FD_ISSET(i,&fdRead))
      {
        if(isServer&&i==listener)
        {
          struct sockaddr_in cl_addr;
          int addrlen=sizeof(cl_addr);
          int newfd=acccept(listener,(struct sockaddr*)&cl_addr,(socklen_t*)&addrlen);
          FD_SET(newfd,&master);
          vverbose<<"-->[ConnectionManager][waitForMessage] new connection created"<<'\n';
          if(newfd>fdmax)
          {
                    
            fdmax=newfd;
          }

        }          
        else
          descr.push_back(i);
      }
    }
    return descr;
  }
  Message ConnectionManager::getMessage(int socket)
  {
    if((isServer&&FD_ISSET(socket,&master))||(!isServer&&serverSocket==socket&&serverSocket!=-2))
    {
      //da completare
    }
  }
    
}

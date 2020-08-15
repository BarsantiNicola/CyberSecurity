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
    fdmax=fileno(stdin);
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
    if(fdmax<listener)
      fdmax=listener;
    return true;
    
  }



  bool ConnectionManager::createConnectionWithServerTCP(const char* IP,int port)
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
    ret=inet_pton(AF_INET,IP,&my_addr.sin_addr);
    if(ret==-1)
    {
      throw invalid_argument("Invalid IP address");
    }
    serverSocket=socket(AF_INET,SOCK_STREAM,0);
    //inet_pton(AF_INET)
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




  bool ConnectionManager::sendMessage(Message message,int socket,const char* recIP,int recPort)
  {  
    int ret;
    uint16_t lmsg;
    Converter* conv=new Converter();
    unsigned char* senderBuffer=new unsigned char[BUFFER_LENGTH];
    initArray(senderBuffer,(unsigned char) '#',BUFFER_LENGTH);
    NetMessage* netmess=conv->encodeMessage(message.getMessageType(),message );
    if(netmess->length()>BUFFER_LENGTH)
    {
      verbose<<"-->[ConnectionManager][sendMessage] Error Message to long"<<'\n';
      delete[]senderBuffer;
      return false;
      }   
 
    if((isServer&&FD_ISSET(socket,&master))||(!isServer&&serverSocket==socket&&serverSocket!=-2))
    {
      
      if(netmess==NULL)
      {
        verbose<<"-->[ConnectionManager][sendMessage] Error conversion"<<'\n';
        delete[]senderBuffer;
        return false;
      }
      copyBuffer(senderBuffer,netmess->getMessage(),BUFFER_LENGTH,netmess->length());
      
      ret=send(socket,(void*)senderBuffer,BUFFER_LENGTH,0);
      if(ret==0)
      {
        verbose<<"-->[ConnectionManager][sendMessage] connection closed"<<'\n';
        closeConnection(socket);
        delete[]senderBuffer;
        return false;
      }
      if(ret<BUFFER_LENGTH)
      {
        verbose<<"-->[ConnectionManager][sendMessage] send message failed"<<'\n';
        delete[]senderBuffer;
        return false;
      }
      return true;
    }
    
    else if(socketUDP==socket)
    {
      struct sockaddr_in reciver_addr;
      memset(&reciver_addr,0,sizeof(reciver_addr));
      reciver_addr.sin_family=AF_INET;
      reciver_addr.sin_port=htons(recPort);
      ret=inet_pton(AF_INET,recIP,&reciver_addr.sin_addr);
      if(ret==-1)
      {
        verbose<<"-->[ConnectionManager][sendMessage] bad reciver address "<<'\n';
        return false;
      }
      
      if(netmess==NULL)
      {
        verbose<<"-->[ConnectionManager][sendMessage] Error conversion"<<'\n';
        return false;
      }
      copyBuffer(senderBuffer,netmess->getMessage(),BUFFER_LENGTH,netmess->length());
      int bufferLength=BUFFER_LENGTH;
      ret=sendto(socket,senderBuffer,bufferLength,0,(struct sockaddr*) &reciver_addr, sizeof(reciver_addr));
      if(ret==0)
      {
        closeConnection(socket);
        verbose<<"-->[ConnectionManager][sendMessage] connection closed"<<'\n';
        return false;
      }
      if(ret<BUFFER_LENGTH)
      {
        verbose<<"-->[ConnectionManager][sendMessage] send message failed"<<'\n';
        return false;
      }
      return true;
    }
  }
 
 /* This function close  a connection and return true in case of success false in case of failure
*/

  bool ConnectionManager::closeConnection(int socket)
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
    for(int i=0;i<=fdmax;i++)
    {
      if(FD_ISSET(i,&fdRead))
      {
        if(isServer&&(i==listener))
        {
          struct sockaddr_in cl_addr;
          int addrlen=sizeof(cl_addr);
          int newfd=accept(listener,(struct sockaddr*)&cl_addr,(socklen_t*)&addrlen);
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

  /*The fuction return a message Type Message from the socket with identifier socket
    return false in case on error*/
  Message* ConnectionManager::getMessage(int socket)
  {
    struct sockaddr_in sender_addr; 
    int addrlen =sizeof(sender_addr);
    if((isServer&&FD_ISSET(socket,&master))||(!isServer&&serverSocket==socket&&serverSocket!=-2))
    {
      int len;
      unsigned char *buffer=new unsigned char[BUFFER_LENGTH];
      
      len=recv(socket,(void*)buffer,BUFFER_LENGTH,0);
      if(len==0)
      {
        verbose<<"-->[ConnectionManager][sendMessage] connection closed"<<'\n';
        delete[]buffer;
        return NULL;
      }
      if (len<BUFFER_LENGTH)
      {
        verbose<<"-->[ConnectionManager][sendMessage] length recived is too short"<<'\n';
        delete[]buffer;
        return NULL;
      }
      int messLength = ReturnIndexLastSimbolPosition(buffer,BUFFER_LENGTH,(unsigned char) '#');
      if(messLength==-1)
      {
        verbose<<"-->[ConnectionManager][sendMessage] the message is NULL"<<'\n';
        delete[]buffer;
        return NULL;
      }
      unsigned char* bufMess=new unsigned char[messLength];
      copyBuffer(bufMess,buffer,messLength,BUFFER_LENGTH);
      NetMessage netmess(bufMess,messLength);
      Converter* conv=new Converter();
      Message* mess=conv->decodeMessage(netmess);
      if(mess==NULL)
      {
        verbose<<"-->[ConnectionManager][sendMessage] the message is NULL"<<'\n';
        delete[]buffer;
        delete[]bufMess;
        delete conv;
        return NULL;
      }
        vverbose<<"-->[ConnectionManager][sendMessage] the message is recived correctly"<<'\n';
        delete[]buffer;
        delete[]bufMess;
        delete conv;
        return mess;
    }

    else if(socketUDP==socket)
    {
      int len;
      unsigned char *buffer=new unsigned char[BUFFER_LENGTH];
      
      len=recvfrom(socket,(void*)buffer,BUFFER_LENGTH,0,(struct sockaddr*)&sender_addr,(socklen_t*)&addrlen);
      if(len==0)
      {
        verbose<<"-->[ConnectionManager][sendMessage] connection closed"<<'\n';
        delete[]buffer;
        return NULL;
      }
      if (len<BUFFER_LENGTH)
      {
        verbose<<"-->[ConnectionManager][sendMessage] length recived is too short"<<'\n';
        delete[]buffer;
        return NULL;
      }
      int messLength = ReturnIndexLastSimbolPosition(buffer,BUFFER_LENGTH,(unsigned char) '#');
      if(messLength==-1)
      {
        verbose<<"-->[ConnectionManager][sendMessage] the message is NULL"<<'\n';
        delete[]buffer;
        return NULL;
      }
      unsigned char* bufMess=new unsigned char[messLength];
      copyBuffer(bufMess,buffer,messLength,BUFFER_LENGTH);
      NetMessage netmess(bufMess,messLength);
      Converter* conv=new Converter();
      Message* mess=conv->decodeMessage( netmess);
      if(mess==NULL)
      {
        verbose<<"-->[ConnectionManager][sendMessage] the message is NULL"<<'\n';
        delete[]buffer;
        delete[]bufMess;
        delete conv;
        return NULL;
      }
        vverbose<<"-->[ConnectionManager][sendMessage] the message is recived correctly"<<'\n';
        delete[]buffer;
        delete[]bufMess;
        delete conv;
        return mess;
    }
  }
/*---------------------------------------------------------------------------------------------*/


  void ConnectionManager::initArray(unsigned char* array,unsigned char elem,int length)
  {
    for(int i=0;i<length;i++)
      array[i]=elem;
  }
/*-------------------------------------------------------------------------------------------*/

  void ConnectionManager:: copyBuffer(unsigned char* arrayOne,unsigned char* arrayTwo,int lengthOne,int lengthTwo)
  { if(lengthOne<0||lengthTwo<0)
     return;
    int minI=0;
    if(lengthOne<= lengthTwo)
      minI=lengthOne;
    else
      minI=lengthTwo;
    for(int i=0;i<minI;i++)
      arrayOne[i]=arrayTwo[i];
  } 

  /*--------------------------------------------------------------------------------------*/
  int ConnectionManager::ReturnIndexLastSimbolPosition(unsigned char* array,int length,unsigned char simbol)
  {
    if(length<0)
     return -1;
    for(int i=(length-1);i>=0;i--)
    {
      if(array[i]!=simbol)
        return i;
    } 
    return -1;
  }
}

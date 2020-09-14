#include"MainClient.h"
namespace client
{
  void MainClient::timerHandler(long secs)
  {
    while(true)
    {
      lck_time->lock();
      if(timer!=0)
      {
        lck_time->unlock();
        sleep(SLEEP_TIME);
        lck_time->lock();
        --timer;
        lck_time->unlock();
      }
      else
      {
        time_expired=true;
        lck_time->unlock();
      }
    }
   
  }
/*
--------------certificateProtocol function-----------------------------
*/
  bool MainClient::certificateProtocol()
  {
   const char*ip=nullptr;
   bool socketIsClosed=false;
   bool res;
   bool DecodRes;
   Message* messRet;
   NetMessage* netRet;
   Converter conv;
   Message* mess =createMessage(MessageType::CERTIFICATE_REQ, nullptr,nullptr,0,nullptr,MessageGameType::NO_GAME_TYPE_MESSAGE);
   if(mess==nullptr)
   {
     verbose<<"-->[MainClient][certificateProtocol] error to create a CERTIFICATION message "<<'\n';
     return false;
   }
   res=connection_manager->sendMessage(*mess,connection_manager->getserverSocket(),&socketIsClosed,ip,0);
 
   try
   {
     messRet=connection_manager->getMessage(connection_manager->getserverSocket());
   }
   catch(exception e)
   {
     notConnected=true;
     return false;
   }
   if(messRet==nullptr)
   {
     verbose<<"-->[MainClient][certificateProtocol] error to recive a CERTIFICATION message "<<'\n';
     return false;
   }
   if(messRet->getMessageType()!=CERTIFICATE)
   {
     verbose<<"-->[MainClient][certificateProtocol] error to recive a CERTIFICATION message "<<'\n';
     return false; 
   }
   vverbose<<"-->[MainClient][certificateProtocol] message recived!!"<<'\n';
   DecodRes=cipher_client->fromSecureForm( messRet , this->username ,nullptr ,true);//da controllare
   
   if(!res||!DecodRes)
   {
     verbose<<"-->[MainClient][certificateProtocol] error certificate protocol!!"<<'\n';
     if(socketIsClosed)
       notConnected=true;
     return false;
   }
    vverbose<<"-->[MainClient][certificateProtocol] message decifred!!"<<'\n';
   netRet=conv.encodeMessage(messRet-> getMessageType(), *messRet );
   if(netRet==nullptr)
   {
     return false;
   }
   vverbose<<"-->[MainClient][certificateProtocol] nonce control"<<'\n';
   this->nonce = *(mess->getNonce())+1;
   //res = cipher_client-> getSessionKey( netRet->getMessage() ,netRet->length() );
   vverbose<<"-->[MainClient][certificateProtocol] sessionKey obtained"<<'\n';
   return res;
  }
/*
--------------------------------loginProtocol function------------------------------
*/
  bool MainClient::loginProtocol(Message message,bool *socketIsClosed)//DA FINIRE
  {
    bool res;
    int* nonce_s;
    bool connection_res;
    Message* retMess;
    Message* sendMess;
    if(message.getMessageType()==LOGIN_REQ)
    {
      res=connection_manager->sendMessage(message,connection_manager->getserverSocket(),socketIsClosed,nullptr,0); 
      if(!res)
      {
        if(socketIsClosed)
          notConnected=true;
        return false;
      }
      try
      {
        retMess=connection_manager->getMessage(connection_manager->getserverSocket());
      }
      catch(exception e)
      {
        notConnected=true;
        return false;
      }
      if(retMess==nullptr)
        return false;

      nonce_s=message.getNonce();
      if(*nonce_s!=this->nonce)
      {
        delete nonce_s;
        return false;
      }
      delete nonce_s;
      res=cipher_client->fromSecureForm( retMess , username ,nullptr,true);
      if(res==false)
      {
        return false;
      }
    
      if(retMess->getMessageType()==LOGIN_OK)
      {
        sendMess=createMessage(MessageType::KEY_EXCHANGE, nullptr,nullptr,0,nullptr,MessageGameType::NO_GAME_TYPE_MESSAGE);
        
        res=connection_manager->sendMessage(message,connection_manager->getserverSocket(),socketIsClosed,nullptr,0); 
        if(!res)
        {
          if(*socketIsClosed)
            notConnected=true;
          return false;
        }
        try
        {
          retMess=connection_manager->getMessage(connection_manager->getserverSocket());
        }
        catch(exception e)
        {
          notConnected=true;
          return false;
        }
        if(retMess==nullptr)
          return false;
        res=keyExchangeReciveProtocol(retMess,true);
        return res;
      }
      else if(retMess->getMessageType()==LOGIN_FAIL)
      {     
        return false;
      }
    }
       
  }
/*
--------------------sendReqUserListProtocol function----------------------------
*/

  bool MainClient::sendReqUserListProtocol()
  {
    bool res;
    bool socketIsClosed=false;
    Message* message;
    message=createMessage(MessageType::USER_LIST_REQ, nullptr,nullptr,0,aesKeyServer,MessageGameType::NO_GAME_TYPE_MESSAGE);
    res=connection_manager->sendMessage(*message,connection_manager->getserverSocket(),&socketIsClosed,nullptr,0);
    if(socketIsClosed)
    {
      vverbose<<"-->[MainClient][sendReqUserProtocol] error server is offline reconnecting"<<'\n';
      notConnected=true;
      return false;
    }
    if(res)
      clientPhase=ClientPhase::USER_LIST_PHASE;
    return res;
  
  }
/*
-------------------receiveUserListProtocol function--------------------------------
*/
    bool MainClient::receiveUserListProtocol(Message* message)
  {
      int* nonce_s;
      bool res;
      if(*nonce_s!=this->nonce)
      {
        verbose<<"--> [MainClient][reciveUserListProtocol] nonce not valid"<<'\n';
        delete nonce_s;
        //clientPhase=ClientPhase::NO_PHASE;
        return false;
      }
      if(message->getMessageType()!=USER_LIST || clientPhase!=ClientPhase::USER_LIST_PHASE)
      {
        verbose<<"--> [MainClient][reciveUserListProtocol] message type not expected"<<'\n';
        return false;
      }
      else
      {
        string app;
        res=cipher_client->fromSecureForm( message , username ,aesKeyServer,false);
        
        if(!res)
          return false; 
        clientPhase=ClientPhase::NO_PHASE;
        unsigned char* userList=message->getUserList();
        int userListLen;
        app=printableString(userList,userListLen);
        std::cout<<app<<endl;
        return true;
      }
  }

/*
--------------------sendRankProtocol function----------------------------
*/

  bool MainClient::sendRankProtocol()
  {
    bool res;
    bool socketIsClosed=false;
    Message* message;
    message=createMessage(MessageType::RANK_LIST_REQ, nullptr,nullptr,0,aesKeyServer,MessageGameType::NO_GAME_TYPE_MESSAGE);
    res=connection_manager->sendMessage(*message,connection_manager->getserverSocket(),&socketIsClosed,nullptr,0);
    if(socketIsClosed)
    {
      vverbose<<"-->[MainClient][sendReqUserProtocol] error server is offline reconnecting"<<'\n';
      notConnected=true;
      return false;
    }
    if(res)
      clientPhase=ClientPhase::RANK_LIST_PHASE;
    return res;
  
  }
/*
-------------------receiveRankProtocol function--------------------------------
*/
    bool MainClient::reciveRankProtocol(Message* message)
  {
      int* nonce_s;
      bool res;
      if(*nonce_s!=this->nonce)
      {
        verbose<<"--> [MainClient][receiveRankProtocol] nonce not valid"<<'\n';
        delete nonce_s;
        //clientPhase=ClientPhase::NO_PHASE;
        return false;
      }
      if(message->getMessageType()!=RANK_LIST || clientPhase!=ClientPhase::RANK_LIST_PHASE)
      {
        verbose<<"--> [MainClient][receiveRankProtocol] message type not expected"<<'\n';
        return false;
      }
      else
      {
        string app;
        res=cipher_client->fromSecureForm( message , username ,aesKeyServer,false);
        
        if(!res)
          return false;
        clientPhase=ClientPhase::NO_PHASE;
        unsigned char* userList=message->getUserList();
        int userListLen;
        app=printableString(userList,userListLen);
        std::cout<<app<<endl;
        return true;
      }
  }

/*
--------------------sendLogoutProtocol---------------------------------------------
*/
  bool MainClient::sendLogoutProtocol()
  {
    bool res;
    bool socketIsClosed=false;
    Message* message;
    message=createMessage(MessageType::LOGOUT_REQ, nullptr,nullptr,0,aesKeyServer,MessageGameType::NO_GAME_TYPE_MESSAGE);
    res=connection_manager->sendMessage(*message,connection_manager->getserverSocket(),&socketIsClosed,nullptr,0);
    if(socketIsClosed)
    {
      vverbose<<"-->[MainClient][sendLogoutProtocol] error server is offline reconnecting"<<'\n';
      notConnected=true;
      return false;
    }
    if(res)
      clientPhase=ClientPhase::LOGOUT_PHASE;
    return res;
  }
/*
---------------------reciveLogoutProtocol----------------------------------
*/
  bool MainClient::receiveLogoutProtocol(Message* message)
  {
      int* nonce_s;
      bool res;
      if(*nonce_s!=this->nonce)
      {
        verbose<<"--> [MainClient][reciveLogoutProtocol] nonce not valid"<<'\n';
        delete nonce_s;
        //clientPhase=ClientPhase::NO_PHASE;
        return false;
      }
      if(message->getMessageType()!=LOGOUT_OK || clientPhase!=ClientPhase::LOGOUT_PHASE)
      {
        verbose<<"--> [MainClient][reciveLogoutProtocol] message type not expected"<<'\n';
        return false;
      }
      else
      {
        res=cipher_client->fromSecureForm( message , username ,aesKeyServer,false);
        if(!res)
          return false; 
        clientPhase=ClientPhase::NO_PHASE;
        logged=false;
        username="";
        return true;
      }
  }

/*
---------------------keyExchangeReciveProtocol--------------------
*/
  bool MainClient::keyExchangeReciveProtocol(Message* message,bool exchangeWithServer)
  {
      unsigned char* app; 
      int len;
      int* nonce_s=message->getNonce();
      bool res;
      nonce_s=message->getNonce();
      if(*nonce_s!=this->nonce)
      {
        verbose<<"--> [MainClient][keyExchangeProtocol] nonce not valid"<<'\n';
        delete nonce_s;
        return false;
      }
      if(message->getMessageType()==KEY_EXCHANGE)
      {
       
        res=cipher_client->fromSecureForm( message , username ,nullptr,exchangeWithServer);
        if(!res)
          return false; 
        app=message->getDHkey();
        len=message->getDHkeyLength();
        if(app==nullptr)
          return false;
        this->aesKeyServer=cipher_client->getSessionKey( app , len );
        delete nonce_s;
        return true;
        
      }
      return false;
  }
 /*
--------------------------------------------createMessage function----------------------------
*/
  Message* MainClient::createMessage(MessageType type, const char* param,unsigned char* g_param,int g_paramLen,cipher::SessionKey* aesKey,MessageGameType messageGameType)
  {
    NetMessage* partialKey;
    NetMessage* net;
    bool cipherRes=true;
    Message* message = new Message();
    switch(type)
    {
      case CERTIFICATE_REQ:
        message->setMessageType( CERTIFICATE_REQ );
        message->setNonce(0);
        break;
      case LOGIN_REQ:
        message->setMessageType( LOGIN_REQ );
        message->setNonce(this->nonce);
        message->setPort( this->myPort );
        message->setUsername(param );
        cipherRes=cipher_client->toSecureForm( message,aesKey);
        this->nonce++;
        break;
        
      case KEY_EXCHANGE:
        message->setMessageType( KEY_EXCHANGE );
        message->setNonce(this->nonce);
        partialKey = this->cipher_client->getPartialKey();
        message->set_DH_key( partialKey->getMessage(), partialKey->length() );
        cipherRes=this->cipher_client->toSecureForm( message,aesKey);
        this->nonce++;
        break;

      case USER_LIST_REQ:
        message->setMessageType(USER_LIST_REQ);
        message->setNonce(this->nonce);
        cipherRes =this->cipher_client->toSecureForm( message,aesKey);
        this->nonce++;
        break;

      case RANK_LIST_REQ:
        message->setMessageType( RANK_LIST_REQ );
        message->setNonce(this->nonce);
        cipherRes =this->cipher_client->toSecureForm( message,aesKey );
        this->nonce++;
        break;

      case LOGOUT_REQ:
        message->setMessageType( LOGOUT_REQ );
        message->setNonce(this->nonce);
        cipherRes=this->cipher_client->toSecureForm( message,aesKey);
        this->nonce++;
        break;

      case ACCEPT:
        message->setMessageType( ACCEPT );
        message->setNonce(this->nonce);
        message->setAdversary_1(param);
        message->setAdversary_2(this->username.c_str());
        cipherRes = this->cipher_client->toSecureForm( message,aesKey);
        this->nonce++;
        break;

      case REJECT:
        message->setMessageType( REJECT );
        message->setNonce(this->nonce);
        message->setAdversary_1(param );
        message->setAdversary_2(this->username.c_str());
        cipherRes = this->cipher_client->toSecureForm( message,aesKey);
        this->nonce++;
        break;

      case WITHDRAW_REQ:
        message->setMessageType( WITHDRAW_REQ );
        message->setNonce(this->nonce);
        message->setUsername(this->username);
        cipherRes = this->cipher_client->toSecureForm( message,aesKey);
        this->nonce++;
        break;

      case MATCH:
        message->setMessageType( MATCH );
        message->setNonce(this->nonce);
        message->setUsername(string(param) );
        cipherRes = this->cipher_client->toSecureForm( message,aesKey);
       // net = Converter::encodeMessage(MATCH, *message );                //da vedere l'utilità in caso cancellare
       // message = this->cipher_client->toSecureForm( message,aesKey );
        this->nonce++;
        break;

      case DISCONNECT:
        message->setMessageType( DISCONNECT );
        message->setNonce(this->nonce);
        message->setUsername(string(param) );
        cipherRes = this->cipher_client->toSecureForm( message,aesKey);
        //net = Converter::encodeMessage(MATCH, *message );               //da vedere l'utilità in caso cancellare
        //message = this->cipher_client->toSecureForm( message,aesKey );
        this->nonce++;
        break;

      case ACK:
        message->setMessageType(ACK);
        switch(messageGameType)
        {
          case MOVE_TYPE:
            message->setCurrent_Token(this->currentToken);
            this->currentToken++;
            break;
          
          case CHAT_TYPE:
            message->setCurrent_Token(this->currTokenChat);
            this->currTokenChat++;
            break;

          case NO_GAME_TYPE_MESSAGE:
            return nullptr;

        }
        cipherRes = this->cipher_client->toSecureForm( message,aesKey);
        
        break;

      case CHAT:
        message->setMessageType(CHAT);     
        message->setCurrent_Token(this->currTokenChat);
        if( g_param==nullptr||aesKey==nullptr)
          return nullptr;
        message->setMessage( g_param,g_paramLen );
        cipherRes = this->cipher_client->toSecureForm( message,aesKey);
        this->currTokenChat++;
        break;

     case GAME:
        message->setMessageType(GAME); 
        message->setCurrent_Token(this->currentToken);
        message->setChosenColumn(  g_param,g_paramLen);
        cipherRes=cipher_client->toSecureForm( message,aesKey );
        break;

    }
    if(!cipherRes)
      return nullptr;
    return message;
  }
/*
---------------------------concatenateTwoField function--------------------------------------
*/
  unsigned char* MainClient::concTwoField(unsigned char* firstField,unsigned int firstFieldSize,unsigned char* secondField,unsigned int secondFieldSize,unsigned char separator,unsigned int numberSeparator)
  {
    if(firstField==nullptr||secondField==nullptr)
      return nullptr;
    int j=0;
    unsigned char* app=new unsigned char[firstFieldSize+secondFieldSize+numberSeparator];
    for(int i=0;i<firstFieldSize;++i)
    {
      app[i]=firstField[i];
    }
    for(int i=firstFieldSize;i<(firstFieldSize+numberSeparator);i++)
    {
      app[i]=separator;
    }
    for(int i=(firstFieldSize+numberSeparator);i<(firstFieldSize+numberSeparator+secondFieldSize);++i)
    {
     
      app[i]=secondField [j];
      ++j;
    }
    return app;
  }
/*
  ------------------------------deconcatenateTwoField function----------------------------------
*/
  bool MainClient::deconcatenateTwoField(unsigned char* originalField,unsigned int originalFieldSize,unsigned char* firstField,unsigned int* firstFieldSize,unsigned char* secondField,unsigned int* secondFieldSize, unsigned char separator,unsigned int numberSeparator)
  {
    int counter=0;
    int firstDimension=0;
    int secondDimension=0;
    if(originalField==nullptr||firstFieldSize==nullptr||secondField==nullptr)
      return false;
    for(int i=0;i<originalFieldSize;++i)
    {
       if(originalField[i]==separator)
       {
         ++counter;
         if(counter==numberSeparator)
         {
           firstDimension = (i-(numberSeparator-1));
           secondDimension= originalFieldSize-i;
         }
       }
       else
       {
         --counter;
       }
    }
    firstField=new unsigned char[firstDimension];
    secondField=new unsigned char[secondDimension];
    for(int i=0;i<firstDimension;++i)
    {
      firstField[i]=originalField[i];      
    }
    int j=0;
    for(int i=(firstDimension+numberSeparator);i<originalFieldSize;++i)
    {    
      secondField[j]=originalField[i];
      ++j;
    }
    *firstFieldSize=firstDimension;
    *secondFieldSize=secondDimension;
    return true;
  }
/*
----------------------function startConnectionServer-----------------------------
*/
bool MainClient::startConnectionServer(const char* myIP,int myPort)
{
  bool res;
  this->myIP=myIP;
  this->myPort=myPort;
  connection_manager=new ConnectionManager(false,this->myIP,this->myPort);
  try
  {
    res=connection_manager->createConnectionWithServerTCP(this->serverIP,this->serverPort);
  }
  catch(exception e)
  {
    res=false;
  }
  return res;
}
/*
------------------------comand function------------------------------------

*/
  bool MainClient::comand(std::string comand_line)
  {
    if(comand_line.empty())
    {
      verbose<<""<<"--> [MainClient][comand] error comand_line is empty"<<'\n';
      return false;
    }
    if(comand_line.compare(0,5,"LOGIN")==0 && logged==false)
    {
      string password;
      string username;
      cout<<"username: "<<endl;
      cin>>username;
      
      
      
      cout<<"password:"<<endl;

      termios oldt;
      tcgetattr(STDIN_FILENO, &oldt);
      termios newt = oldt;
      newt.c_lflag &= ~ECHO;
      tcsetattr(STDIN_FILENO, TCSANOW, &newt);//hide input
      std::cin>>password;
      tcsetattr(STDIN_FILENO, TCSANOW, &oldt);//show input
     
      if(username.empty()||password.empty())
      {
        std::cout<<"username or password not valid"<<endl;
      }
      cipher_client->newRSAParameter(username,password);
      if(!cipher_client->getRSA_is_start())
      {
         std::cout<<"login failed retry"<<endl;
         std::cout<<"\t# Insert a command:";
      }
      else
      {
        this->username=username;
        this->logged=true;
        textual_interface_manager->printMainInterface(this->username," ","online","none","0");
      }
      return true;
    }
    else if(comand_line.compare(0,4,"show ")==0)
    {
      if(comand_line.compare(5,11,"[users]")==0)
      {
        if(!sendReqUserListProtocol())
        {
          std::cout<<"show user online failed retry"<<endl;
          std::cout<<"\t# Insert a command:";
        }
      }
      else if(comand_line.compare(5,11,"[users]")==0)
      {
        if(!sendRankProtocol())
        {
          std::cout<<"show user online failed retry"<<endl;
          std::cout<<"\t# Insert a command:";
        }
      }
    }
    else if(comand_line.compare(0,9,"challenge ")==0)
    {
      //ESEGUO CHALLENGE
    }
    else if(comand_line.compare(0,6,"logout ")==0&&logged==true)
    {
      //ESEGUO LOGOUT
      bool ret=sendLogoutProtocol();
      if(!ret)
      {
          std::cout<<"logout failed retry"<<endl;
          std::cout<<"\t# Insert a command:";
      }
    }
    return true;
  }

  MainClient::MainClient(const char* ipAddr , int port )
  {
    this->myIP=ipAddr;
    this->myPort=port;
  }
/*
------------------------MainClient----------------------------------
*/
  void MainClient::client()
  {
     
     std::vector<int> sock_id_list;
     int newconnection_id=0;
     string newconnection_ip="";
     lck_time=new std::unique_lock<std::mutex>(mtx_time,std::defer_lock);

     textual_interface_manager=new TextualInterfaceManager();
     bool res;
    while(true)
    {
       if(notConnected==true)
       {
         res=startConnectionServer(this->myIP,this->myPort);
         if(!res)
           exit(1);

     
         if(!certificateProtocol())
           exit(1);
         textual_interface_manager->printLoginInterface();
         notConnected=false;
        }

      string comand_line;
      sock_id_list= connection_manager->waitForMessage(&newconnection_id,&newconnection_ip);
      if(!sock_id_list.empty())
      {
        for(int idSock: sock_id_list)
        {
          if(idSock==connection_manager->getstdinDescriptor())
          {
            std::cin>>comand_line;
            comand(comand_line);
          }
          if(idSock==connection_manager->getserverSocket())
          {
            
            Message* message=connection_manager->getMessage(connection_manager->getserverSocket());
            if(message==nullptr)
              continue;
           
            switch(message->getMessageType())
            {
              case LOGOUT_OK:
                if(clientPhase==ClientPhase::LOGOUT_PHASE)
                {
                    res=receiveLogoutProtocol(message);
                    if(!res)
                      continue;
                    textual_interface_manager->printLoginInterface();
                }
                break;
              case USER_LIST:
               if(clientPhase==ClientPhase::USER_LIST_PHASE)
               {
                 res=receiveUserListProtocol(message);
                 if(!res)
                 {
                   cout<<"error to show the online user list"<<endl;
                   std::cout<<"\t# Insert a command:";
                 }
               }
               break;
              case RANK_LIST:
               if(clientPhase==ClientPhase::RANK_LIST_PHASE)
               {
                 res=receiveUserListProtocol(message);
                 if(!res)
                 {
                   cout<<"error to show the online user list"<<endl;
                   std::cout<<"\t# Insert a command:";
                 }
               }
               break;
              case ERROR:
              {
                res=cipher_client->fromSecureForm( message , username ,aesKeyServer,true);
                if(res==false)
                {
                  break;
                }
                cout<<"error to server request try again."<<endl;
                clientPhase=ClientPhase::NO_PHASE;
                std::cout<<"\t# Insert a command:";
                break;
              }
              default:
                 verbose<<"--> [MainClient][client] message_type unexpected"<<'\n';
            }
          }
        }
        
      }
    }
  }
/*


--------------------------utility function---------------------------------------
*/
  string MainClient::printableString(unsigned char* toConvert,int len)
  {
    char* app=new char[len+1];
    string res="";
    for(int i =0;i<len;i++)
    {
      app[i]=toConvert[i];
    }
    app[len]='\0';
    res.append(app);
    delete[] app;
    return res;
  }

}

/*
--------------------main function-----------------
*/  
int main(int argc, char** argv)
{
    Logger::setThreshold(  VERY_VERBOSE );
    client::MainClient* main_client;
    if(argc==1)
    {
      main_client=new client::MainClient("127.0.0.1",12000);
      main_client->client();
    }
    return 0;
}

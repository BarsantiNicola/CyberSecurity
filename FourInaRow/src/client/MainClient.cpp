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
   DecodRes=cipher_client->fromSecureForm( mess , this->username ,nullptr ,true);
   if(!res||!DecodRes)
     return false;
    messRet=connection_manager->getMessage(connection_manager->getserverSocket());
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
   netRet=conv.encodeMessage(messRet-> getMessageType(), *messRet );
   if(netRet==nullptr)
   {
     return false;
   }
   this->nonce = *(mess->getNonce())+1;
   res = cipher_client-> getSessionKey( netRet->getMessage() ,netRet->length() );
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
        return false;

      retMess=connection_manager->getMessage(connection_manager->getserverSocket());
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
          return false;
        retMess=connection_manager->getMessage(connection_manager->getserverSocket());
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
---------------------keyExchangeReciveProtocol--------------------
*/
  bool MainClient::keyExchangeReciveProtocol(Message* message,bool exchangeWithServer)
  {
      unsigned char* app; 
      int len;
      int* nonce_s=message->getNonce();
      bool res;
      if(*nonce_s!=this->nonce)
      {
        vverbose<<"--> [MainClient][keyExchangeProtocol] nonce not valid";
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
    bool cipherRes=false;
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
    if(comand_line.compare(0,5,"LOGIN "))
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
      delete cipher_client;
      cipher_client=new cipher::CipherClient(username,password);
      if(!cipher_client->getRSA_is_start())
      {
         std::cout<<"login failed retry"<<endl;
         std::cout<<"\t# Insert a command:";
      }
      else
      {
        this->username=username;
        textual_interface_manager->printMainInterface(this->username," ","online","none","0");
      }
      return true;
    }
    else if(comand_line.compare(0,4,"show "))
    {
      //ESEGUO LO SHOW
    }
    else if(comand_line.compare(0,9,"challenge "))
    {
      //ESEGUO CHALLENGE
    }
    else if(comand_line.compare(0,6,"logout "))
    {
      //ESEGUO LOGOUT
    }
    return true;
  }

  MainClient::MainClient(const char* ipAddr , int port )
  {
    this->myIP=ipAddr;
    this->myPort=port;
  }

  void MainClient::client()
  {
     std::vector<int> sock_id_list;
     int newconnection_id=0;
     string newconnection_ip="";
     lck_time=new std::unique_lock<std::mutex>(mtx_time,std::defer_lock);

     textual_interface_manager=new TextualInterfaceManager();
     bool res;
     res=startConnectionServer(this->myIP,this->myPort);
     if(!res)
       exit(1);

     
    if(!certificateProtocol())
      exit(1);
    textual_interface_manager->printLoginInterface();
    
    while(true)
    {
      string comand_line;
      sock_id_list= connection_manager->waitForMessage(&newconnection_id,&newconnection_ip);
      if(!sock_id_list.empty())
      {
        for(int idSock: sock_id_list)
        {
          if(idSock==connection_manager->getstdinDescriptor())
          {
            cin>>comand_line;
            comand(comand_line);
          }
        }
        
      }
    }
  }



}
/*
-------------main function--------------
*/  
int main(int argc, char** argv)
{
    Logger::setThreshold(  VERY_VERBOSE );
    client::MainClient* main_client;
    if(argc==0)
    {
      main_client=new client::MainClient("127.0.0.1",1235);
      main_client->client();
    }
    return 0;
}

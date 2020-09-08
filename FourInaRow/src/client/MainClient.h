#include"Game.h"
#include<string>
#include"../cipher/CipherClient.h"
#include"../utility/Message.h"
#include"../utility/NetMessage.h"
#include"../utility/Converter.h"
#include"ChallengeInformation.h"
#include"ChallengeRegister.h"
#include"TextualInterfaceManager.h"
#include"../utility/ConnectionManager.h"
using namespace cipher;
namespace client
{
  class MainClient
  {
    private:
      Game* game;
      ChallengeRegister* challenge_register;
      ConnectionManager connection_manager;
      TextualInterfaceManager textual_interface_manager;
      CipherClient* cipher_client;
      bool loginProtocol(NetMessage netmessage);
      bool signUpProtocol(NetMessage netmessage);
      bool challengeProtocol(NetMessage netmessage);
      bool acceptProtocol(NetMessage netmessage);
      bool rejectProtocol(NetMessage netmessage);
      bool rankProtocol(NetMessage netmessage);
      bool certificateProtocol();
      bool keyExchangeProtocol(NetMessage netmessage);
      bool userListProtocol(NetMessage netmessage);
      bool disconnectProtocol(NetMessage netmessage);
      bool logoutProtocol(netMessage netmessage);
      bool matchProtocol(netMessage netmessage);
      bool timerHandler(long secs);
    public:
      int main(int argc, char** argv); 
  };


}

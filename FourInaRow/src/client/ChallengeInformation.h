#include<string>
using namespace std;
namespace client
{
  class ChallengeInformation
  {
    private:
      string username="";
      int totalMatch=0;
      double wonPercent=0;
    public:
      ChallengeInformation(string userName,int totalMatch,double wonPercent);
      ChallengeInformation(string username);
      ChallengeInformation(const ChallengeInformation& challengeInfo);
      string getUserName();
      int getTotalMatch();
      double getWonPercent();
      string printChallengeInformation();
      
  };

}

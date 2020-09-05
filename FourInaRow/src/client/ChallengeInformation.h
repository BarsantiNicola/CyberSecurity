#include<string>
using namespace std;
namespace client
{
  class ChallengeInformation
  {
    private:
      string username="";
      int totalMatch;
      double wonPercent;
    public:
      ChallengeInformation(string userName,int totalMatch,double wonPercent);
      ChallengeInformation(ChallengeInformation& challengeInfo);
      string getUserName();
      int getTotalMatch();
      double getWonPercent();
      string printChallengeInformation();
      
  };

}

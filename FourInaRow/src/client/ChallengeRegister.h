#include<string>
#include"ChallengeInformation.h"
#include<exception>
#include<stdexcept>
#include<vector>
using namespace std;
namespace client
{
  class ChallengeRegister
  {
    private:
      vector<ChallengeInformation> challengeInformationList;
    public:
      bool addData(ChallengeInformation data);
      bool removeData(ChallengeInformation data);
      bool findData(ChallengeInformation data);
      int getDimension();
      ChallengeInformation* getData(int dataPosition);
      string printChallengeList();
      ~ChallengeRegister();
  };
}

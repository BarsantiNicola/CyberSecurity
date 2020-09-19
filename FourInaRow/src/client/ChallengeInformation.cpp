#include"ChallengeInformation.h"
namespace client
{
  /*
  Costructor that permit to create a challenge information
  */
  ChallengeInformation::ChallengeInformation(string username,int totalMatch,double wonPercent)
  {
    if(!username.empty())
      this->username=username;
    this->totalMatch=totalMatch;
    this->wonPercent=wonPercent;
  }

  ChallengeInformation::ChallengeInformation(string username)
  {
    if(!username.empty())
      this->username=username;
    this->totalMatch=0;
    this->wonPercent=0;
  }

  /*
  Copy costructor
 */

  ChallengeInformation::ChallengeInformation(const ChallengeInformation& challengeInfo)
  {
    if(!challengeInfo.username.empty())
      this->username=challengeInfo.username;
    this->totalMatch=challengeInfo.totalMatch;
    this->wonPercent=challengeInfo.wonPercent;
  }
/*
 -----------------------------------------get methods-------------------------------------

*/

  string ChallengeInformation::getUserName()
  {
    return username;
  }

  int ChallengeInformation::getTotalMatch()
  {
    return totalMatch;
  }


  double ChallengeInformation::getWonPercent()
  {
    return wonPercent;
  }

/*
--------print class method
*/
  string ChallengeInformation::printChallengeInformation()
  {
    string challenge=username + "\t" + to_string(totalMatch) + "\t" + to_string(wonPercent) +"\t";
    return challenge;
  }

}


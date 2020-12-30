#include"ChallengeRegister.h"

namespace client
{
 bool ChallengeRegister::addData(ChallengeInformation data)
 {
   try
   {
     challengeInformationList.emplace_back(data);
     return true;
   }
   catch(bad_alloc& e)
   {
     return false;
   }
 }


 ChallengeInformation* ChallengeRegister::getData(int dataPosition)
 {
   if (dataPosition<0)
   {
     return nullptr;
   }
   try
   {
     
     return &challengeInformationList.at(dataPosition);
   }
   catch(out_of_range& e)
   {
     return nullptr;
   }
 }

 string ChallengeRegister::printChallengeList()
 {
   string res="";
   for(int i=0;i<challengeInformationList.size();i++)
   {
     try
     {
       res+=challengeInformationList.at(i).printChallengeInformation();
     }
     catch(out_of_range& e)
     {
       break;
     }
   }
   return res;
 }
 bool ChallengeRegister::findData(ChallengeInformation data)
 {
   
   for(int i=0;i<challengeInformationList.size();i++)
   {
     try
     {
       if(challengeInformationList.at(i).equals(&data))
       {
          return true;
       }
     }
     catch(out_of_range& e)
     {
       break;
     }
   }
   return false;   
 }
 int ChallengeRegister::getDimension()
 {
   return challengeInformationList.size();
 }
 bool ChallengeRegister::removeData(string username)
 {
   for(int i=0;i<challengeInformationList.size();i++)
   {
     try
     {
       if(challengeInformationList.at(i).getUserName().compare(username)==0)
       {
          challengeInformationList.erase(challengeInformationList.begin()+i);
          return true;
       }
     }
     catch(out_of_range& e)
     {
       break;
     }
   }
   return false;
 }
 bool ChallengeRegister::removeData(ChallengeInformation data)
 {
   for(int i=0;i<challengeInformationList.size();i++)
   {
     try
     {
       if(challengeInformationList.at(i).equals(&data))
       {
          challengeInformationList.erase(challengeInformationList.begin()+i);
          return true;
       }
     }
     catch(out_of_range& e)
     {
       break;
     }
   }
   return false;
 }
 ChallengeRegister::~ChallengeRegister()
 {
   challengeInformationList.clear();
 }

 vector<string> ChallengeRegister:: getUserlistString()
 {
   vector<string> vectorRes;
   for(int i=0;i<challengeInformationList.size();i++)
   {
     try
     {
       vectorRes.emplace_back(challengeInformationList.at(i).getUserName());
     }
     catch(out_of_range& e)
     {
       break;
     }
   }
   return vectorRes;
 }
 void ChallengeRegister::clearRegister()
 {
   challengeInformationList.clear();
   vverbose<<"-->[ChallengeRegister][clearRegister] clear complete size:"<<(int)challengeInformationList.size()<<'\n';
 }
}

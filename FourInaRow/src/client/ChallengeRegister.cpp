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
}

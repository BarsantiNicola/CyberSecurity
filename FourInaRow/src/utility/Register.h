#include<stdexcept>
#include<vector>
#include <ostream>
#include <cstring>
#include "../Logger.h"
using namespace std;
namespace utility{
 class UserInformation;
 class MatchInformation;
 class ClientInformation;
 template<typename T>
 class Register{
  protected:
   vector<T> dataList;
  public:
   Register();
   T* getData(T data);
   bool removeData(T);
   bool addData(T);
   T* getDatafromIndex(unsigned int);
   ~Register();
  //protected:
   //bool addData(T);
   //T getData(int);
 };
}


#include<stdexcept>
#include<vector>
#include <ostream>
#include <cstring>
#include "../Logger.h"
using namespace std;
namespace utility{

 template<typename T>
 class Register{
  protected:
   vector<T> dataList;
  public:
   Register();
   bool removeData(T);
   ~Register();
  protected:
   bool addData(T);
   T getData(int);
 };
}


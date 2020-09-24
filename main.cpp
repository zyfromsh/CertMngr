#include <iostream>
#include <cstdlib>
#include <string>
#include <cstring>
#include <cctype>
#include <thread>
#include <chrono>
#include <vector>
#include <map>
#include "CertMngr.h"
#include "MQTTModels.h"
#include "log.h"


using namespace std;

int main()
{
    //  SetUnhandledExceptionFilter(ExceptionFilter);
    CertMngr *test = new CertMngr();
    CSRReqParam param;
    param.CountryName = "CN";
    param.StateName = "Shanghai";
    param.LocalityName = "Shanghai";
    param.OrgName = "Honeywell";
    param.OrgUnitName = "HPS";
    param.CommonName = "rtu.1231231.honeywell.com";
    char csrFilePath[100] = {0};
    
    test->Init();

    test->GenerateCSR(param, csrFilePath);

    //// EventLog(0, "start test install cert");
    // string certSource="/home/foo/CertMngr/bin/caout/rtu.1231231.honeywell.com.cer";
    //test->InstallCert(certSource.c_str());

    //  vector<CertInfo> certs=test->GetInstalledCerts();

    //  for (size_t i = 0; i < certs.size(); i++)
    //  {
    //      CertInfo one=certs[i];
    //      EventLog(0,"cn:%s,filename:%s",one.CommonName.c_str(),one.FileName.c_str());
    //      /* code */
    //  }
     
   //  test->InstallTrustChain("/home/foo/CertMngr/bin/caout/ca.honeywell.com.p7b");

    

    //vector<CertInfo> certs=test->GetInstalledCerts();








    return 1;
}

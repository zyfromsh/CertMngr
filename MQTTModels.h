#ifndef _MQTTModels_H_INCLUDE
#define _MQTTModels_H_INCLUDE
#include <iostream>
#include <string>
using namespace std;


struct CSRReqParam{
    string CountryName;
    string StateName;
    string LocalityName;
    string OrgName;
    string OrgUnitName;
    string CommonName;
};

struct CertInfo{
    string CommonName;
    string FileName;
    string Subject;
};

struct TrustChainInfo{
    string FileName;
    string CommonName;
};

struct CRLInfo{
    string FileName;
    string CommonName;
};

#endif
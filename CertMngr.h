#ifndef _CETMNGR_H_INCLUDE
#define _CETMNGR_H_INCLUDE
#include <stdio.h>
#include <string.h>
#include "MQTTModels.h"


class CertMngr{
    private:
    string _CertRootDir;
    string _CADir="ca/";
    string _CertDir="cert/";
    string _CSRDir="csr/";
    string _TmpDir="tmp/";
    string _OpensslConfig="client.conf";
    int GetCertInfoFromFile(string filePath , CertInfo* cerInfo);
    int GetCrlInfoFromFile(string filePath, CRLInfo* crlInfo);
  public:
  void Init();
  
  //csr
  int GenerateCSR(CSRReqParam csrReqParam,  char* csrFilePath); 
  //crt
  int InstallCert(const char* sourceCertFilePath);
  vector<CertInfo> GetInstalledCerts();
  int UninstallCert(CertInfo* cert);
  
  //trust chain
  int InstallTrustChain(const char* trustChainPath);
  vector<TrustChainInfo*> GetTrustChain();
  int UninstallTrustChain(TrustChainInfo* trustChain);
  
  //crl 
  int InstallCRL(const char* sourceCRLPath);
  vector<CRLInfo*> GetCRL();
  int UninstallCRL(CRLInfo* crl);

  void Test(); 
};



#endif
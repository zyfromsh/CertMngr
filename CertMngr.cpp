#include <iostream>
#include <fstream>
#include <cstdlib>
#include <string>
#include <cstring>
#include <cctype>
#include <thread>
#include <chrono>
#include <vector>
#include <unistd.h>
#include <regex>
#include <map>
// #include <sys/io.h>
#include <io.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include "CertMngr.h"
#include "MQTTModels.h"
#include "log.h"
#include "platutil.h"

using namespace std;

void CertMngr::Init()
{
    _CertRootDir = "/home/foo/CertMngr/bin/";
    string capath = _CertRootDir + _CADir;
    if (access(capath.c_str(), F_OK) != 0)
    {
        // make directory for configuration files
        if (mkdir(capath.c_str(), 0777) != 0)
        {
        }
    }

    string certpath = _CertRootDir + _CertDir;
    if (access(certpath.c_str(), F_OK) != 0)
    {
        // make directory for configuration files
        if (mkdir(certpath.c_str(), 0777) != 0)
        {
        }
    }
    string csrpath = _CertRootDir + _CSRDir;
    if (access(csrpath.c_str(), F_OK) != 0)
    {
        // make directory for configuration files
        if (mkdir(csrpath.c_str(), 0777) != 0)
        {
        }
    }

    string tmpPath = _CertRootDir + _TmpDir;
    if (access(tmpPath.c_str(), F_OK) != 0)
    {
        // make directory for configuration files
        if (mkdir(tmpPath.c_str(), 0777) != 0)
        {
        }
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////
// Function description : generate private key and csr file of der format,same CommonName generate one csr and key
// Input parameters     : None
// Output parameters    : csrFilePath-path of csr file
// Return               : bool - True if success, otherwise failed
// Note                 :
//////////////////////////////////////////////////////////////////////////////////////////////////////
int CertMngr::GenerateCSR(const CSRReqParam csrReqParam, char *csrFilePath)
{

    string keyPath = this->_CertRootDir + this->_CertDir + csrReqParam.CommonName + ".key";
    string csrPath = this->_CertRootDir + this->_CSRDir + csrReqParam.CommonName + ".csr.der";
    string configPath = this->_CertRootDir + this->_OpensslConfig;

    char subject[500] = {0};
    sprintf(subject, "-subj /C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/", csrReqParam.CountryName.c_str(), csrReqParam.StateName.c_str(), csrReqParam.LocalityName.c_str(), csrReqParam.OrgName.c_str(), csrReqParam.OrgUnitName.c_str(), csrReqParam.CommonName.c_str());

    char cmd[1024] = {0};
    sprintf(cmd, "openssl req -newkey rsa:2048  -nodes  -outform der -config %s -out %s -keyout %s ", configPath.c_str(), csrPath.c_str(), keyPath.c_str());

    strcat(cmd, subject);

    cout << cmd << endl;
    char result[2048] = {0};
    ExecuteCMD(cmd, result);

    //check if csr and private key are created successfully or not
    bool keyExist = access(keyPath.c_str(), F_OK) == 0;
    if (!keyExist)
    {
        //log key is not exist;
        return 1;
    }

    bool csrExist = access(csrPath.c_str(), F_OK) == 0;
    if (!csrExist)
    {
        //log key is not exist;
        return 2;
    }

    strcat(csrFilePath, csrPath.c_str());

    return 0;
};

//////////////////////////////////////////////////////////////////////////////////////////////////////
// Function description : the format of source file is der, so need to convert it to pem,then copy to cert direcotry
// Input parameters     : None
// Output parameters    : csrFilePath-path of csr file
// Return               : bool - True if success, otherwise failed
// Note                 :
//////////////////////////////////////////////////////////////////////////////////////////////////////
int CertMngr::InstallCert(const char *sourceCertFilePath)
{
    bool fileExist = access(sourceCertFilePath, F_OK) == 0;
    if (!fileExist)
    {
        //log file not exists;
        return 1;
    }
    //todo:check certificate already exists or not by file name

    //copy to certificate directory
    string pemFilePath = this->_CertRootDir + this->_TmpDir + GetFileNameFromPath(sourceCertFilePath);
    string derFileName = pemFilePath + ".der";
    bool copySuccess = CopyFile(sourceCertFilePath, derFileName.c_str(), 0, 0);
    if (!copySuccess)
    {
        return 1;
    }

    //convert der to pem
    char cmd[200];
    sprintf(cmd, "openssl x509 -in %s -inform der -out %s", derFileName.c_str(), pemFilePath.c_str());

    char result[200];

    ExecuteCMD(cmd, result);
    //todo: check convert is success or not

    bool success = access(pemFilePath.c_str(), F_OK) == 0;
    if (!success)
    {
        //log fail to install

        //clean tmp file
        return 1;
    }

    //check if key of certificate exists or not
    CertInfo *certInfo = new CertInfo();

    int state = GetCertInfoFromFile(pemFilePath, certInfo);

    if (state != 0)
    {
        //get cert info error
        return 1;
    }

    string privateKeyPath = _CertRootDir + _CertDir + certInfo->CommonName + ".key";

    if (access(privateKeyPath.c_str(), F_OK) != 0)
    {

        //log：no private key
        return 1;
    }

    //check trust chain
    string capath = _CertRootDir + _CADir;
    sprintf(cmd, "openssl verify -CApath %s %s", capath.c_str(), pemFilePath.c_str());
    ExecuteCMD(cmd, result);
    string resStr = result;
    if (resStr.find("OK") == string::npos)
    {
        //check trust chain fail
        return 1;
    }

    //copy crt from tmp to cert
    string des = _CertRootDir + _CertDir + certInfo->CommonName + ".crt";
    success = CopyFile(pemFilePath.c_str(), des.c_str(), 0, 0);

    if (!success)
    {
        //log copy fail
        return 1;
    }

    //clean tmp file
    remove(derFileName.c_str());
    remove(pemFilePath.c_str());

    return 0;
}
void CertMngr::Test()
{
    char *cmd = "dir .";
    char content[512] = {0};
    ExecuteCMD(cmd, content);
    string s = string(content);
    cout << s << endl;
};

vector<CertInfo> CertMngr::GetInstalledCerts()
{

    vector<CertInfo> certs;

    string to_search = _CertRootDir + _CertDir;
    DIR *dir;
    struct dirent *ptr;
    string x, dirPath;
    dir = opendir((char *)to_search.c_str()); //打开一个目录
    while ((ptr = readdir(dir)) != NULL)      //循环读取目录数据
    {
        EventLog(0, "d_name : %s\n", ptr->d_name); //输出文件名
        string fileName = ptr->d_name;
        string suffix = GetFileSuffixFromPath(fileName);
        if (suffix == "" || suffix != "crt")
        {
            continue;
        }

        CertInfo cert;
        cert.FileName = fileName; //        x = dirPath.c_str();
        certs.push_back(cert);
    }
    closedir(dir); //关闭目录指针

    return certs;
}

int CertMngr::UninstallCert(CertInfo *cert)
{
    //todo:only delete .crt file
    string crtPath = _CertRootDir + _CertDir + cert->FileName;

    remove(crtPath.c_str());
    return 0;
}
//only support pem format certificate
int CertMngr::GetCertInfoFromFile(string filePath, CertInfo *cerInfo)
{

    bool fileExist = access(filePath.c_str(), F_OK) == 0;
    if (!fileExist)
    {
        //log file not exists;
        return 1;
    }

    string cmd = "openssl x509 -in " + filePath + " -noout  -subject";

    char result[1024]={0};

    ExecuteCMD(cmd.c_str(), result);

    regex pattern("CN = (.*)");
    cmatch matchResult;
    bool matchSuccess=regex_search(result, matchResult, pattern);
    if (matchSuccess)
    {
        csub_match cs = matchResult[1];
        cerInfo->CommonName = cs.str();
        cerInfo->Subject = result;
        return 0;
    }
    return 1;
}

int CertMngr::InstallTrustChain(const char *trustChainPath)
{

    if (access(trustChainPath, F_OK) != 0)
    {
        //log no p7b file
        return 1;
    }

    //copy p7b to tmp
    string fileName = GetFileNameFromPath(trustChainPath);
    string tmpP7bPath = _CertRootDir + _TmpDir + fileName;

    CopyFile(trustChainPath, tmpP7bPath.c_str(), 0, 0);

    //extract to tmp folder
    string tmpPath = _CertRootDir + _TmpDir;
    char cmd[600] = {0};
    sprintf(cmd, "openssl pkcs7  -print_certs -in %s  -inform der | \
    awk 'BEGIN {c=0; start=0} /BEGIN CERTIFICATE/{c++; start=1} /END CERTIFICATE/{start=0; print > \"%s\" c \".p7btmp.crt\"} { if (start) print > \"%s\" c \".p7btmp.crt\"}'",
            tmpP7bPath.c_str(), tmpPath.c_str(), tmpPath.c_str());

    char result[1024]={0};
    ExecuteCMD(cmd, result);
    //get trust chain  cert info from tmp folder
    vector<CertInfo *> certs;
    DIR *dir;
    struct dirent *ptr;
    string x, dirPath;
    dir = opendir((char *)tmpPath.c_str()); //打开一个目录
    while ((ptr = readdir(dir)) != NULL)       //循环读取目录数据
    {
        EventLog(0, "d_name : %s\n", ptr->d_name); //输出文件名
        string fileName = ptr->d_name;

        size_t index = fileName.find(".p7btmp.crt");
        if (index == string::npos)
        {
            continue;
        }
        CertInfo *cert = new CertInfo();
        GetCertInfoFromFile(tmpPath + fileName, cert);
        cert->FileName = fileName;
        certs.push_back(cert);
    }
    closedir(dir); //关闭目录指针

    //move to ca folder,filename is common name,
    for (int i = 0; i < certs.size(); i++)
    {
        CertInfo *cert = certs[i];
        string soureFile = tmpPath + cert->FileName;
        string des = _CertRootDir + _CADir + cert->CommonName + ".crt";
        CopyFile(soureFile.c_str(), des.c_str(), 0, 0);
    }

    //todo::execute openssl c_rehash ca/

    //extract crl from p7b if crl exists
    string tmpcrl = _CertRootDir + _TmpDir + ".p7btmp.crl";
    sprintf(cmd, "openssl pkcs7  -print_certs -in %s  -inform der | \
    |sed -n '/-BEGIN X509 CRL/,/-END X509 CRL/p;/-END X509 CRL/q' > %s",
            tmpP7bPath.c_str(), tmpcrl.c_str());
            
    memset(result,'\0',sizeof(result));
    ExecuteCMD(cmd, result);

    if (access(tmpcrl.c_str(), F_OK) != 0)
    {
        //p7b may doesn't contain crl
        return 0;
    }



    //copy crl from tmp to ca ,and rename by common name
    CRLInfo* crlInfo=new CRLInfo();
    int state=GetCrlInfoFromFile(tmpcrl,crlInfo);
    if(state!=0)
    {
        return 1;
    }

    string des=_CertRootDir+_CADir+crlInfo->CommonName+".crl";
    state=CopyFile(tmpcrl.c_str(),des.c_str(),0,0)?0:1;
    return state;

}

vector<TrustChainInfo *> CertMngr::GetTrustChain()
{

    vector<TrustChainInfo *> trustChains;

    DIR *dir;
    struct dirent *ptr;
    string x, dirPath;
    string caPath = _CertRootDir + _CADir;
    dir = opendir(caPath.c_str());       //打开一个目录
    while ((ptr = readdir(dir)) != NULL) //循环读取目录数据
    {
        EventLog(0, "d_name : %s\n", ptr->d_name); //输出文件名
        string fileName = ptr->d_name;
        string suffix = GetFileSuffixFromPath(fileName);
        if (suffix == "" || suffix != "crt")
        {
            continue;
        }

        CertInfo *cert = new CertInfo();
        GetCertInfoFromFile(caPath + fileName, cert);
        TrustChainInfo *caChain = new TrustChainInfo();
        caChain->CommonName = cert->CommonName;
        caChain->FileName = fileName;
        trustChains.push_back(caChain);
    }
    closedir(dir); //关闭目录指针

    return trustChains;
}

//delete file by file name
int CertMngr::UninstallTrustChain(TrustChainInfo *trustChain)
{

    string certFile = _CertRootDir + _CADir + trustChain->FileName;
    if (access(certFile.c_str(), F_OK) != 0)
    {
        //log no file；
        return 1;
    }

    remove(certFile.c_str());
    return 0;
}

int CertMngr::InstallCRL(const char *sourceCRLPath)
{
    if (access(sourceCRLPath, F_OK) != 0)
    {
        return 1;
    }

    //convert der to pem and output to tmp dir
    string cmd=" openssl crl -in ";
    cmd.append(sourceCRLPath);
    cmd.append("  -inform der -out ");
    string fileName=GetFileNameFromPath(sourceCRLPath);
    string tmpPath=_CertRootDir+_TmpDir+""+fileName;
    cmd.append(tmpPath);
    char result[1024]={0};
    ExecuteCMD(cmd.c_str(),result);

    if(access(tmpPath.c_str(),F_OK)!=0)
    {
        //log convert fail
        return 1;
    }

    //copy to ca dir and rename by common name,end up with .crl

    CRLInfo* crlInfo=new CRLInfo();
    GetCrlInfoFromFile(tmpPath,crlInfo);
    string des=_CertRootDir+_CADir+crlInfo->CommonName+".crl";
    
    CopyFile(tmpPath.c_str(),des.c_str(),0,0);
    return 0;

}

vector<CRLInfo *> CertMngr::GetCRL()
{
    vector<CRLInfo *> crls;
    DIR *dir;
    struct dirent *ptr;
    string x, dirPath;
    string capath = _CertRootDir + _CADir;
    dir = opendir((char *)capath.c_str()); //打开一个目录
    while ((ptr = readdir(dir)) != NULL)   //循环读取目录数据
    {
        EventLog(0, "d_name : %s\n", ptr->d_name); //输出文件名
        string fileName = ptr->d_name;
        string suffix = GetFileSuffixFromPath(fileName);
        if (suffix == "" || suffix != "crl")
        {
            continue;
        }

        CRLInfo *crl = new CRLInfo();
        crl->FileName = fileName;
        crls.push_back(crl);
    }
    closedir(dir); //关闭目录指针

    return crls;
}
int CertMngr::UninstallCRL(CRLInfo *crl)
{
    string crlFilePath = _CertRootDir + _CADir + crl->FileName;
    if (access(crlFilePath.c_str(), F_OK) != 0)
    {
        //log no file；
        return 1;
    }

    remove(crlFilePath.c_str());
    return 0;
}

int CertMngr::GetCrlInfoFromFile(string filePath, CRLInfo *crlInfo)
{
    if (access(filePath.c_str(), F_OK) != 0)
    {
        //log no file；
        return 1;
    }


    string cmd="openssl crl -in "+filePath+" -issuer  -noout";
    char result[400];
    ExecuteCMD(cmd.c_str(),result);

    //get issuer
    regex pattern("CN = (.*?)$");
    cmatch matchResult;

    if (regex_search(result, matchResult, pattern))
    {
        csub_match cs = matchResult[1];
        crlInfo->CommonName=cs.str();
        return 0;
    }
    return 1;

}

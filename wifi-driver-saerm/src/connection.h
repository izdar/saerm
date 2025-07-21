#ifndef CONNECTION_H_
#define CONNECTION_H_

# include "allIncludes.h"
# include "warningmsgs.h"

extern "C"{
# include "sendFrame.h"
}

class connectState
{
private:
     //SSID, password, source-mac, dest-mac, interfacename, physical name
     int sockfd ; 
     string SSID, password, ifaceName, phyName ; 
     bool IsSSIDSet, IsPasswordSet, IsIFaceNameSet, IsPhyNameSet ; 
     bool IsSrcMACSet, IsDestMACSet, IsSockfdSet ; 
     bool AreTheInterfacesInitialized ; 
public: 

    unsigned char sourceMAC[6];
    unsigned char destMAC[6] ; 


    string getSSID() ; 
    string getPassword() ; 
    string getIFaceName() ; 
    string getPhyName() ; 
    int getSocket() ; 
    void connectionState();
    int read_sockfd();
    void connectionState(string , string , string , string , unsigned char [], unsigned char []) ; 
    void setConnectionInformation(string , string , string , string , unsigned char [], unsigned char []) ;
    void setSSID(string ) ; 
    void setPassword(string ) ; 
    void setIFaceName(string ) ; 
    void setPhyName(string ) ; 
    void setSrcMAC(unsigned char []);
    void setDestMAC(unsigned char []) ; 
    void createSocket() ; 
    void closeSocket(); 
};

#endif 
# include "connection.h" 


int connectState::getSocket(){
    WarningMessages::PositiveConditionMsg(this->IsSockfdSet, "Socket is not created..."); 
    return this->sockfd ; 
}
string connectState::getSSID(){
    WarningMessages::PositiveConditionMsg(IsSSIDSet, "Trying to get the SSID without setting");
    return SSID ; 
}
string connectState::getPassword() {
    WarningMessages::PositiveConditionMsg(IsPasswordSet, "Trying to get the Password without setting"); 
    return password ;

} 
string connectState::getIFaceName(){
    WarningMessages::PositiveConditionMsg(IsIFaceNameSet, "Tryuing to get the IFACE without setting"); 
    return ifaceName ; 
} 
string connectState::getPhyName(){
    WarningMessages::PositiveConditionMsg(IsPhyNameSet, "Trying to get Physical name without setting");
    return phyName ; 
}
void connectState::connectionState(){
    IsSSIDSet = IsPasswordSet = IsIFaceNameSet = IsPhyNameSet = IsSrcMACSet = IsDestMACSet = IsSockfdSet = AreTheInterfacesInitialized = false ;
}
void connectState::connectionState(string ssid, string Password, string iFacename, string PhyName, unsigned char srcMAC[], unsigned char destmac[])
{
    SSID = ssid ; password = Password ; ifaceName = iFacename ; phyName = PhyName ; 
    for(int i = 0 ; i < 6 ; ++i){ 
        sourceMAC[i] = srcMAC[i]; 
        destMAC[i] = destmac[i] ;
    } 
    IsSSIDSet = IsPasswordSet = IsIFaceNameSet = IsPhyNameSet = IsSrcMACSet = IsDestMACSet =  true ;
    IsSockfdSet = false ; 
    AreTheInterfacesInitialized = false ; 

}
void connectState::setConnectionInformation(string ssid, string Password, string iFacename, string PhyName, unsigned char srcMAC[], unsigned char destmac[]){
    
    WarningMessages::WarningWithoutCrashPositive(!IsSSIDSet && !IsPasswordSet && !IsIFaceNameSet && !IsPhyNameSet && !IsSrcMACSet &&  !IsDestMACSet, "RESETTING SOME VARIABLES WITH SET CONNECTION INFORMATION") ; 
    SSID = ssid ; password = Password ; ifaceName = iFacename ; phyName = PhyName ; 
    for(int i = 0 ; i < 6 ; ++i){ 
        sourceMAC[i] = srcMAC[i]; 
        destMAC[i] = destmac[i] ;
    } 
    IsSSIDSet = IsPasswordSet = IsIFaceNameSet = IsPhyNameSet = IsSrcMACSet = IsDestMACSet =  true ;
    IsSockfdSet = false ; 
    AreTheInterfacesInitialized = false ; 
}
void connectState::setSSID(string ssid){
    WarningMessages::WarningWithoutCrashPositive(!IsSSIDSet, "Resetting SSID"); 
    this->SSID = ssid ; 
    this->IsSSIDSet = true ; 
}
void connectState::setPassword(string password){
    WarningMessages::WarningWithoutCrashPositive(!(this->IsPasswordSet), "Resetting Password"); 
    this->password = password ; 
    this->IsPasswordSet = true ; 
} 
void connectState::setIFaceName(string ifacename){
    WarningMessages::WarningWithoutCrashPositive(!(this->IsIFaceNameSet), "Resetting IFace Name");
    this->ifaceName = ifaceName ; 
    this->IsIFaceNameSet = true ; 

} 
void connectState::setPhyName(string phyname){
    WarningMessages::WarningWithoutCrashPositive(!(this->IsPhyNameSet), "Resetting Physical Name"); 
    this->phyName = phyName ; 
    this->IsIFaceNameSet = true ; 
}
void connectState::setSrcMAC(unsigned char srcmac[]){
    WarningMessages::WarningWithoutCrashPositive(!(this->IsSrcMACSet), "Resetting Source MAC") ; 
    for(int i = 0 ; i < 6 ; ++i){ 
        sourceMAC[i] = srcmac[i]; 
    } 
    this->IsSrcMACSet = true ; 

}
void connectState::setDestMAC(unsigned char destmac[]){
    WarningMessages::WarningWithoutCrashPositive(!(this->IsDestMACSet), "Resetting Destination MAC"); 
    this->IsDestMACSet = true ; 
}

int connectState::read_sockfd() {
    FILE *file = fopen("sockfd.txt","r");
    WarningMessages::PositiveConditionMsg(file != NULL, "File is null??");
    int sockfd;
    if (fscanf(file, "%d", &sockfd) != 1) {
        printf("Could not read socket file descriptor\n");
        return -1;
    }
    fclose(file);
    return sockfd;
}


void connectState::createSocket(){
    WarningMessages::PositiveConditionMsg(this->IsIFaceNameSet && this->IsPhyNameSet, "Either the ifacename or the physical name is not set"); 
    WarningMessages::NegativeConditionMsg(this->AreTheInterfacesInitialized, "Interfaces have already been initialized"); 
#ifdef AP
    initialize_interfaces(getPhyName().c_str(), getIFaceName().c_str());
#endif
    this->sockfd = create_monitor_socket(this->getIFaceName().c_str());
    this->IsSockfdSet = true ; 
    this->AreTheInterfacesInitialized = true ; 
} 

void connectState::closeSocket(){
    WarningMessages::PositiveConditionMsg(this->IsSockfdSet, "Socket is not opened"); 
    close(this->sockfd) ; 
}
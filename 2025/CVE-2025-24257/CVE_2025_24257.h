//
//  CVE_2025_24257.h
//  IOGPUFamily bitmap_mask underflow → kernel heap OOB write
//
//  Researcher: Wang Yu of Cyberserval (original discovery)
//

#import <Foundation/Foundation.h>

void trigger_CVE_2025_24257(void);

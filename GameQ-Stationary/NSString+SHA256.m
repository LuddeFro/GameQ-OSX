//
//  NSString+SHA256.m
//  GameQ
//
//  Created by Ludvig Fröberg on 4/21/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import "NSString+SHA256.h"
#import <CommonCrypto/CommonDigest.h>

@implementation NSString(SHA256)

- (NSString*)SHA256
{
    // Create pointer to the string as UTF8
    const char *ptr = [self UTF8String];
    
    // Create byte array of unsigned chars
    unsigned char sha256Buffer[CC_SHA256_DIGEST_LENGTH];
    
    // Create 16 byte MD5 hash value, store in buffer
    //convert ULInt to uInt to avoid compile warning from CC_MD5() method
    uint ptr2 = (uint)strlen(ptr);
    CC_SHA256(ptr, ptr2, sha256Buffer);
    
    // Convert MD5 value in the buffer to NSString of hex values
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x",sha256Buffer[i]];
    
    return output;
}

@end
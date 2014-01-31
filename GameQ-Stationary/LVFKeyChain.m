//
//  LVFKeyChain.m
//  GameQ-Stationary
//
//  Created by Ludvig Fröberg on 29/11/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import "LVFKeyChain.h"

@implementation LVFKeyChain

    
- (void) setPassword:(NSString *)pass
{
    LVFDataModel *dataHandler = [[LVFDataModel alloc] init];
    
    OSStatus status;
    UInt32 serviceLen = (UInt32)kAPPID.length;
    UInt32 accountLen = (UInt32)dataHandler.getEmail.length;
    
    const char service = (const char)kAPPID;
    const char account = (const char)dataHandler.getEmail;
    
    
    SecKeychainItemRef itemRef = nil;
    UInt32 passLen = (UInt32)nil;
    void* pwd = nil;
    status = SecKeychainFindGenericPassword (
                                              NULL,           // default keychain
                                              serviceLen,             // length of service name
                                              &service,   // service name
                                              accountLen,             // length of account name
                                              &account,   // account name
                                              &passLen,  // length of password
                                              pwd,   // pointer to password data
                                              &itemRef         // the item reference
                                              );
    if (status == errSecItemNotFound){
        pwd = (__bridge void *)(pass);
        passLen = (UInt32)pass.length;
        status = SecKeychainAddGenericPassword(NULL, serviceLen, &service, accountLen, &account, passLen, pwd, NULL);
    } else if (status == noErr){
        pwd = (__bridge void *)(pass);
        passLen = (UInt32)pass.length;
        status = SecKeychainItemModifyAttributesAndData (
                                                         Nil,         // the item reference
                                                         NULL,            // no change to attributes
                                                         passLen,  // length of password
                                                         pwd         // pointer to password data
                                                         );
    }
    
    
    
}
    
- (NSString *) getPassword;
{
    LVFDataModel *dataHandler = [[LVFDataModel alloc] init];
    
    OSStatus status;
    UInt32 serviceLen = (UInt32)kAPPID.length;
    UInt32 accountLen = (UInt32)dataHandler.getEmail.length;
    
    const char service = (const char)kAPPID;
    const char account = (const char)dataHandler.getEmail;
    
    
    SecKeychainItemRef itemRef = nil;
    UInt32 passLen = (UInt32)nil;
    void* pwd = nil;
    status = SecKeychainFindGenericPassword (
                                             NULL,           // default keychain
                                             serviceLen,             // length of service name
                                             &service,   // service name
                                             accountLen,             // length of account name
                                             &account,   // account name
                                             &passLen,  // length of password
                                             pwd,   // pointer to password data
                                             &itemRef         // the item reference
                                             );
    NSString *pass = (__bridge NSString *)(pwd);
    return pass;
    
}
    
@end

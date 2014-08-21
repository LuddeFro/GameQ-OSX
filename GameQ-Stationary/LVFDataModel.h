//
//  LVFdataModel.h
//  GameQ-Mobile
//
//  Created by Ludvig Fröberg on 10/23/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "LVFAppDelegate.h"
#import "LVFDefinitions.h"
#import "LVFKeyChain.h"
#import "SSKeychain.h"


@class LVFAppDelegate;

@interface LVFDataModel : NSObject

@property (strong, nonatomic) NSManagedObjectContext *context;
@property (strong, nonatomic) NSFetchRequest *request;
@property LVFAppDelegate *appDelegate;
@property (strong, nonatomic) NSManagedObject *myObject;

- (void) setToken:(NSString *)token;
- (void) setEmail:(NSString *)email;
- (void) setBolIsLoggedIn:(NSNumber *)isLoggedIn;
- (void) setDeviceID:(NSString *)devID;
- (void) setPass:(NSString *)pass;
- (void) setFirstLog:(NSString *)pass;
- (void) setUniqueID:(NSString *)string;

- (NSString *) getToken;
- (NSString *) getEmail;
- (NSNumber *) getBolIsLoggedIn;
- (NSString *) getDeviceID;
- (NSString *) getPass;
- (NSString *) getFirstLog;
- (NSString *) getUniqueID;


-(id) initWithAppDelegate:(LVFAppDelegate *)appDel;

@end

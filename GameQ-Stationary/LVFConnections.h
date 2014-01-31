//
//  LVFConnections.h
//  NetMonitor
//
//  Created by Ludvig Fröberg on 10/19/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "NSString+MD5.h"
#import "LVFConnect.h"
#import "LVFAppDelegate.h"
@class LVFConnect;
@interface LVFConnections : NSObject

@property LVFConnect *gqConnect;


- (void)UpdateStatusWithGame:(NSNumber *)game andStatus:(NSNumber *)status;
- (void)logoutPost;
- (void)loginWithUser:(NSString*)username andPass:(NSString*)losenord;
- (void)pushNotificationForGame:(NSNumber *)game;
- (void) getSecretPost:(NSString*)email;
- (void) chkSecretForEmail:(NSString*)email withSecret:(NSString*)secret andSecretQuestion:(NSString*)secretq;
- (void)registerWithEmail:(NSString*)email andPass:(NSString*)losenord andSecretQuestion:(NSString*)secretQuestion andSecret:(NSString*)secret andFirsName:(NSString*)firstname andLastName:(NSString*)lastname andGender:(int)gender andYOB:(NSString*)yob andCountry:(NSString*)country;

// mobile method
//- (void)upAppPost;

@end

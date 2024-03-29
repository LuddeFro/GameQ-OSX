//
//  LVFConnections.h
//  NetMonitor
//
//  Created by Ludvig Fröberg on 10/19/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "NSString+SHA256.h"
#import "LVFConnect.h"
#import "LVFAppDelegate.h"
@class LVFConnect;
@interface LVFConnections : NSObject

@property LVFConnect *gqConnect;


- (void)UpdateStatusWithGame:(NSNumber *)game andStatus:(NSNumber *)status andToken:(NSString *)token;
- (void)logoutPostFromToken:(NSString *)token;
- (void)loginWithUser:(NSString*)username andPass:(NSString*)losenord;
- (void)pushNotificationForGame:(NSNumber *)game andToken:(NSString *)token andEmail:(NSString *)email;
- (void) getSecretPost:(NSString*)email;
- (void) chkSecretForEmail:(NSString*)email withSecret:(NSString*)secret andSecretQuestion:(NSString*)secretq;
- (void)registerWithEmail:(NSString*)email andPass:(NSString*)losenord andSecretQuestion:(NSString*)secretQuestion andSecret:(NSString*)secret andFirsName:(NSString*)firstname andLastName:(NSString*)lastname andGender:(int)gender andYOB:(NSString*)yob andCountry:(NSString*)country;
- (void) upTimeForToken:(NSString *)token;
- (void) upTokenWithToken:(NSString *)token andDeviceName:(NSString *)name andEmail:(NSString *)email;
- (void) postNewSecretQuestion:(NSString *)secretq andSecret:(NSString *)secret forEmail:(NSString *)email andPassword:(NSString *)losenord;
- (void) postNewPassword:(NSString *)newLosenord forEmail:(NSString *)email andOldPassword:(NSString *)losenord;
- (void) postNewDeviceName:(NSString *)deviceName forToken:(NSString *)token andEmail:(NSString *)email;
- (void) chkVersion;
// mobile method
//- (void)upAppPost;

@end

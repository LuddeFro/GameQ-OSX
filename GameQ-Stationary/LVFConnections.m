//
//  LVFConnections.m
//  NetMonitor
//
//  Created by Ludvig Fröberg on 10/19/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import "LVFConnections.h"


@interface LVFConnections ()


@end


@implementation LVFConnections

@synthesize gqConnect;

- (id) init
{
    self = [super init];
    if (self)
    {
        gqConnect = [[LVFConnect alloc] initWithDelegate:self];
    }
    return self;
    
}

- (void)loginWithUser:(NSString*)username andPass:(NSString*)losenord
{
    losenord = [losenord MD5];
    NSString *postString = [NSString stringWithFormat:@"email=%@&losenord=%@",username, losenord];
    NSString *postUrl = loginURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"login posted");
}
/** if registering in app ever happens
- (void)registerWithEmail:(NSString*)email andPass:(NSString*)losenord andSecretQuestion:(NSString*)secretQuestion andSecret:(NSString*)secret
{
    losenord = [losenord MD5];
    NSString *postString = [NSString stringWithFormat:@"email=%@&losenord=%@&secretq=%@&secret=%@",email, losenord, secretQuestion, secret];
    NSString *postUrl = registerURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"signup posted");
}
*/

//softPush a status update from a game to 
- (void)UpdateStatusWithGame:(NSNumber *)game andStatus:(NSNumber *)status
{
    NSString *postString = [NSString stringWithFormat:@"game=%@&status=%@", game, status];
    NSString *postUrl = softPushURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"status update posted");
}
//Push notification, for now all pushes are sent for recieved queue
- (void)pushNotificationForGame:(NSNumber *)game
{
    NSString *postString = [NSString stringWithFormat:@"game=%@", game];
    NSString *postUrl = pushURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"addonepost");
}
//Log the client out
- (void)logoutPost
{
    NSString *postString = @"";
    NSString *postUrl = logoutURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"logout posted");
}

/* used in mobile version to retrieve status data from server
- (void)upAppPost
{
    NSString *postString = @"";
    NSString *postUrl = updateURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"upapppost");
}
 */




/*
   following methods used if support is added in-app for forgotten passwords
    also see connectionDidFinishLoading method in Connect.m for commented out if statements
 
- (void) getSecretPost:(NSString*)email
{
    NSString *postString = [NSString stringWithFormat:@"email=%@", email];
    NSString *postUrl = getSecretURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"get secret posted");
}

 - (void) chkSecretForEmail:(NSString*)email withSecret:(NSString*)secret andSecretQuestion:(NSString*)secretq
{
    NSString *postString = [NSString stringWithFormat:@"secret=%@&secretQ=%@&email=%@", secret, secretq, email];
    NSString *postUrl = checkSecretURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"check secret posted");
}
*/







@end

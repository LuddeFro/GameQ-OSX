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
    

 // register
- (void)registerWithEmail:(NSString*)email andPass:(NSString*)losenord andSecretQuestion:(NSString*)secretQuestion andSecret:(NSString*)secret andFirsName:(NSString*)firstname andLastName:(NSString*)lastname andGender:(int)gender andYOB:(NSString*)yob andCountry:(NSString*)country
{
    losenord = [losenord MD5];
    secret = [secret MD5];
    NSString *postString = [NSString stringWithFormat:@"email=%@&losenord=%@&secretq=%@&secret=%@&firstname=%@&lastname=%@&gender=%d&yob=%@&country=%@",email, losenord, secretQuestion, secret, firstname, lastname, gender, yob, country];
    NSString *postUrl = registerURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"signup posted");
}


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






 
- (void) getSecretPost:(NSString*)email
{
    NSString *postString = [NSString stringWithFormat:@"email=%@", email];
    NSString *postUrl = getSecretURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"get secret posted");
}

 - (void) chkSecretForEmail:(NSString*)email withSecret:(NSString*)secret andSecretQuestion:(NSString*)secretq
{
    
    secret = [secret MD5];
    NSString *postString = [NSString stringWithFormat:@"secret=%@&secretQ=%@&email=%@", secret, secretq, email];
    NSString *postUrl = checkSecretURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"check secret posted");
}

    
- (void) registerWithEmailmmmOSV{
    
}







@end

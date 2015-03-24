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
    
    losenord = [losenord SHA256];
    NSString *postString = [NSString stringWithFormat:@"email=%@&losenord=%@",username, losenord];
    NSString *postUrl = loginURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"login posted");
}
    

 // register
- (void)registerWithEmail:(NSString*)email andPass:(NSString*)losenord andSecretQuestion:(NSString*)secretQuestion andSecret:(NSString*)secret andFirsName:(NSString*)firstname andLastName:(NSString*)lastname andGender:(int)gender andYOB:(NSString*)yob andCountry:(NSString*)country
{
    NSLog(@"registering from _connectionshandler");
    losenord = [losenord SHA256];
    secret = [secret SHA256];
    NSString *postString = [NSString stringWithFormat:@"email=%@&losenord=%@&secretq=%@&secret=%@&firstname=%@&lastname=%@&gender=%d&yob=%@&country=%@",email, losenord, secretQuestion, secret, firstname, lastname, gender, yob, country];
    NSLog(@"%@", postString);
    NSString *postUrl = registerURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"signup posted");
}


//softPush a status update from a game to 
- (void)UpdateStatusWithGame:(NSNumber *)game andStatus:(NSNumber *)status andToken:(NSString *)token
{
    NSDate *dateValue = [NSDate date];
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyyMMdd"];
    [dateFormatter setTimeZone:[NSTimeZone timeZoneWithName:@"Europe/Stockholm"]];
    NSString *date = [dateFormatter stringFromDate:dateValue];
    NSString *vCode = [NSString stringWithFormat:@"%@%@jam", token, date].SHA256;
    //NSString *postString = [NSString stringWithFormat:@"game=%@&status=%@&token=abcdefg&device=mac", game, status];
    NSString *postString = [NSString stringWithFormat:@"game=%@&status=%@&token=%@&device=mac&vCode=%@", game, status, token, vCode];
    NSString *postUrl = softPushURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"status update posted ");
}
//Push notification, for now all pushes are sent for recieved queue
- (void)pushNotificationForGame:(NSNumber *)game andToken:(NSString *)token andEmail:(NSString *)email
{
    NSDate *dateValue = [NSDate date];
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyyMMdd"];
    [dateFormatter setTimeZone:[NSTimeZone timeZoneWithName:@"Europe/Stockholm"]];
    NSString *date = [dateFormatter stringFromDate:dateValue];
    NSString *vCode = [NSString stringWithFormat:@"%@%@jam", token, date].SHA256;
    NSString *postString = [NSString stringWithFormat:@"game=%@&token=%@&device=mac&email=%@&vCode=%@", game, token, email, vCode];
    //NSString *postString = [NSString stringWithFormat:@"game=%@&token=abcdefg&device=mac&email=%@", game, email];
    NSString *postUrl = pushURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"addonepost %@ %@", game, token);
    NSUserNotification *notif = [[NSUserNotification alloc] init];
    [notif setTitle:@"GameQ"];
    [notif setInformativeText:@"Your queue has ended!"];
    [notif setDeliveryDate:[NSDate dateWithTimeIntervalSinceNow:1]];
    
    //[notif setContentImage:[NSImage imageNamed:@"NotificationLogo.png"]];
    NSUserNotificationCenter *center = [NSUserNotificationCenter defaultUserNotificationCenter];
    [center scheduleNotification:notif];
    
}
//Log the client out
- (void)logoutPostFromToken:(NSString *)token
{
    
    NSString *postString = [NSString stringWithFormat:@"token=%@&device=mac", token];
    NSString *postUrl = logoutURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"logout posted");
}

//quit the client out
- (void)quitPostFromToken:(NSString *)token
{
    
    NSString *postString = [NSString stringWithFormat:@"token=%@", token];
    NSString *postUrl = quitURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"quit posted");
}

- (void) monitorMeForEmail:(NSString *)email
{
    NSString *postString = [NSString stringWithFormat:@"email=%@", email];
    NSString *postUrl = monitorMeURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"monme posted");
}

- (void) upTimeForToken:(NSString *)token
{
    
    NSString *postString = [NSString stringWithFormat:@"token=%@&device=mac", token];
    NSString *postUrl = timeURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"timeUpdated (connection active)");
}

- (void) upTokenWithToken:(NSString *)token andDeviceName:(NSString *)name andEmail:(NSString *)email
{
    [gqConnect postNow:[NSString stringWithFormat:@"token=abc123&device=%@&email=%@", /*todotoken, */name, email] to:updateTokenURL];
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



- (void)sendMissReport:(NSString *)report forGame:(int)game
{
    NSString *postString = [NSString stringWithFormat:@"report=%@&game=%d", report, game];
    NSString *postUrl = reportURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"report sent for game %d", game);
}

- (void) chkVersion
{
    NSString *postString = [NSString stringWithFormat:@"device=mac"];
    NSString *postUrl = versionURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"version checked");
}

 
- (void) getSecretPost:(NSString*)email
{
    NSString *postString = [NSString stringWithFormat:@"email=%@", email];
    NSString *postUrl = getSecretURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"get secret posted");
}

 - (void) chkSecretForEmail:(NSString*)email withSecret:(NSString*)secret andSecretQuestion:(NSString*)secretq
{
    
    secret = [secret SHA256];
    NSString *postString = [NSString stringWithFormat:@"secret=%@&secretQ=%@&email=%@", secret, secretq, email];
    NSString *postUrl = checkSecretURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"check secret posted");
}



- (void) postNewSecretQuestion:(NSString *)secretq andSecret:(NSString *)secret forEmail:(NSString *)email andPassword:(NSString *)losenord
{
    secret = [secret SHA256];
    losenord = [losenord SHA256];
    NSString *postString = [NSString stringWithFormat:@"secretq=%@&secret=%@&email=%@&losenord=%@", secretq, secret, email, losenord];
    NSString *postUrl = updateSecretURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"Posted new secret");
}
- (void) postNewPassword:(NSString *)newLosenord forEmail:(NSString *)email andOldPassword:(NSString *)losenord
{
    gqConnect.shortTermMemory = newLosenord;
    NSLog(@"%@", [NSString stringWithFormat:@"newLosenord=%@&email=%@&losenord=%@", newLosenord, email, losenord]);
    newLosenord = [newLosenord SHA256];
    losenord = [losenord SHA256];
    NSString *postString = [NSString stringWithFormat:@"newLosenord=%@&email=%@&losenord=%@", newLosenord, email, losenord];
    NSString *postUrl = updatePasswordURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"Posted new password");
}
- (void) postNewDeviceName:(NSString *)deviceName forToken:(NSString *)token andEmail:(NSString *)email
{
    NSString *postString = [NSString stringWithFormat:@"deviceName=%@&token=%@&email=%@", deviceName, token, email];
    NSString *postUrl = updateDeviceURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"Posted new device Name");
}

- (void) checkPhones:(NSString *)email
{
    NSString *postString = [NSString stringWithFormat:@"email=%@", email];
    NSString *postUrl = checkPhonesURL;
    [gqConnect postNow:postString to:postUrl];
    NSLog(@"Posted phone check");
}









@end

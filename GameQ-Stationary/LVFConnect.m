//
//  LVFResponses.m
//  NetMonitor
//
//  Created by Ludvig Fröberg on 10/19/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import "LVFConnect.h"

@interface LVFConnect ()

@property NSMutableData *returnData;
@property NSMutableURLRequest *request;
@property BOOL disconnected;
@property LVFConnections *delegate;
@property LVFAppDelegate *appDel;

@end

@implementation LVFConnect
@synthesize disconnected;
@synthesize request;
@synthesize returnData;
@synthesize delegate;
@synthesize appDel;


- (id) initWithDelegate:(LVFConnections *)del
{
    self = [super init];
    if (self) {
        delegate = del;
    }
    appDel = [[NSApplication sharedApplication] delegate];
    return self;
}

- (void)postNow:(NSString*)toPost to:(NSString*)link
{
    NSString *postString = toPost;
    NSData *postData = [postString dataUsingEncoding:NSUTF8StringEncoding];
    NSString *postLength = [NSString stringWithFormat:@"%lu", (unsigned long)[postData length]];
    
    request = [[NSMutableURLRequest alloc] init];
    [request setURL:[NSURL URLWithString:link]];
    [request setHTTPMethod:@"POST"];
    [request setValue:postLength forHTTPHeaderField:@"Content_Length"];
    [request setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    [request setHTTPBody:postData];
    NSURLConnection *postConnection = [[NSURLConnection alloc] initWithRequest:request delegate:self];
    if (postConnection)
    {
        returnData = [NSMutableData data];
    }
    else
    {
        
        [self connectionAlert:@"conErr1"];
        NSLog(@"login connection failed");
    }
    NSLog(@"postNow method has finished executing");
}

// setting up the connection and error handling
- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    [returnData setLength:0];
}
- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    [returnData appendData:data];
}
- (void)connection:(NSURLConnection *)connection
  didFailWithError:(NSError *)error
{
    returnData = NULL;
    
    NSLog(@"Connection failed! Error - %@ %@",
          [error localizedDescription],
          [[error userInfo] objectForKey:NSURLErrorFailingURLStringErrorKey]);
}

//connection was successful, handle response here
- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    NSLog(@"received data length:%lu", (unsigned long)[returnData length]);
    NSString *returnString = [[NSString alloc] initWithData:returnData encoding:NSUTF8StringEncoding];
    NSLog(@"%@", returnString);
    NSLog(@"return string above");
    
    
    
     
    //secret question has been retrieved, response syntax "secQ%@", secretQuestion
    if (returnString.length >= 4) {
        if ([[returnString substringWithRange:NSMakeRange(0, 4)] isEqualToString:@"secQ"])
        {
            [appDel setupAnswerWithQuestion:[returnString substringFromIndex:4]];
        }
    }
    
     
    if ([returnString isEqualToString:@"wronguser"])
    {
        [self connectionAlert:@"No such user exists!"];
        return;
    }
    if ([returnString isEqualToString:@"wrongsecret"])
    {
        [self connectionAlert:@"The answer you supplied is incorrect!"];
        return;
    }
    
    
    if ([returnString isEqualToString:@"pwdreset"])
    {
        [[NSAlert alertWithMessageText:@"GameQ" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Congratulations on signing up for GameQ! Please check your E-mail address for a temporary password that is required the first time you log in!"] runModal];
        return;
    }
    
    
    if ([returnString isEqualToString:@"postedDevice"])
    {
        NSLog(@"updated token and device name");
        return;
    }
    
    
    
    
    
    
    // if sign in was successful
    if ([returnString isEqualToString:@"sign in success"])
    {
        [appDel setConnected];
        return;
    }
    
    // if sign in failed
    if ([returnString isEqualToString:@"sign in failed"])
    {
        [[NSAlert alertWithMessageText:@"Invalid login details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"You entered an invalid password - username combination, please try again.\r\n\r\nToo many failed attempts may lock your account for up to 2 hours."] runModal];
        [appDel setDisconnected];
        
        return;
    }
    
    //if you just logged out
    if ([returnString isEqualToString:@"logged out"])
    {
        if (!disconnected)
        {
            //if you logged out manually
            NSLog(@"logged out");
            [appDel setDisconnected];
            return;
        }
        else {
            //if you got "badsession" already sends an alert, this method is simply here for future use
            disconnected = false;
        }
    }
    /* historic profile edit from lottery
    if ([returnString isEqualToString:@"updated me"])
    {
        if (btnInvis.enabled == true)
            [self myProfileFinTransitDelayed];
        else
            [self myProfileFinTransit];
        btnSave.enabled = true;
        return;
    }
    if ([returnString isEqualToString:@"wrongpassword"])
    {
        [[[UIAlertView alloc] initWithTitle:@"Free Lottery" message:@"A correct current password is required" delegate:self cancelButtonTitle:@"OK" otherButtonTitles:nil] show];
        lastName.text = @"";
    }
     */
     
    if ([returnString isEqualToString:@"yes"])
    {
        return;
    }
    if ([returnString isEqualToString:@"signing up"])
    {
        [appDel setupLogin];
        [[NSAlert alertWithMessageText:@"GameQ" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Registration was successful! A temporary password has been sent to your e-mail account for your first log in!"] runModal];
        return;
    }
    if ([returnString isEqualToString:@"duplicate"])
    {
        [self connectionAlert:@"An account with that e-mail address already exists!"];
        return;
    }
    
    if ([returnString isEqualToString:@"badsession"])
    {
        //attempt to reconnect? or record disconnection and logout
        disconnected = true;
        [delegate logoutPostFromToken:[appDel.dataHandler getToken]];
        [appDel setDisconnected];
       
        //stationary alert
        [self connectionAlert:@"badSession"];
        
        // mobile alert
        //[[[UIAlertView alloc] initWithTitle:@"GameQ" message:@"You were disconnected from the server, please try reconnecting!" delegate:self cancelButtonTitle:@"OK" otherButtonTitles:nil] show];
        return;
    }
    if ([returnString isEqualToString: @"no"])
    {
        //should be unreachable, disconnect the bastard!
        disconnected = true;
        [delegate logoutPostFromToken:[appDel.dataHandler getToken]];
        [appDel setDisconnected];
        
        //statioanry alert
        [self connectionAlert:@"&no"];
        
        // mobile alert
        //[[[UIAlertView alloc] initWithTitle:@"GameQ" message:@"Connection error, please try again in a minute" delegate:self cancelButtonTitle:@"OK" otherButtonTitles:nil] show];
    } else {
        [self connectionAlert:@"666"];
    }
}

- (void) connectionAlert:(NSString*)code
{
    [[NSAlert alertWithMessageText:@"GameQ Connection Error" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Error Code: %@", code] runModal];
}

@end

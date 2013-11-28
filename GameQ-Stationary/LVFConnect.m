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
        
        [[NSAlert alertWithMessageText:@"GameQ could not establish a connection" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Please check you network connections and try again!"] runModal];
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
    
    
    /* following statements used if support is added in-app for forgotten passwords
     also see getSecret and chkSecret methods in LVFConnections.m
     
    //secret question has been retrieved, response syntax "secQ%@", secretQuestion
    if ([[returnString substringWithRange:NSMakeRange(0, 4)] isEqualToString:@"secQ"])
    {
        
        txtSecretQ.text = [returnString substringFromIndex:4];
        if (btnInvis.enabled == true)
        {
     
        }
        else
        {
     
        }
        btnForget.enabled = true;
        
    }
     
    if ([returnString isEqualToString:@"wronguser"])
    {
        [[[UIAlertView alloc] initWithTitle:@"Free Lottery" message:@"Invalid e-mail address" delegate:self cancelButtonTitle:@"OK" otherButtonTitles:nil] show];
        btnForget.enabled = true;
        return;
    }
    if ([returnString isEqualToString:@"wrongsecret"])
    {
        [[[UIAlertView alloc] initWithTitle:@"Free Lottery" message:@"Wrong secret" delegate:self cancelButtonTitle:@"OK" otherButtonTitles:nil] show];
        btnSave.enabled = true;
        return;
    }
    
     
    if ([returnString isEqualToString:@"pwdreset"])
    {
        [self loginRight];
        [self secRight];
        if (btnInvis.enabled == true)
        {
            [self completeAnimationsDelayed];
            [self rollRightDelayed];
            [self toggleKeyboard:btnInvis];
        }
        else
        {
            [self completeAnimations];
            [self rollRight];
            [self toggleKeyboard:btnInvis];
        }
        [[[UIAlertView alloc] initWithTitle:@"Free Lottery" message:@"Your password has been  reset, a temporary password has been sent to your e-mail address" delegate:self cancelButtonTitle:@"OK" otherButtonTitles:nil] show];
        btnSave.enabled = true;
        return;
    }
     */
    
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
    /* if forgotten password support is added in-app
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
     
    /*
     If registering is enabled from client
    if ([returnString isEqualToString:@"signing up"])
    {
        if (btnInvis.enabled == true)
            [self signupFinTransitDelayed];
        else
            [self signupFinTransit];
        [self goTutorial:btnTutorial];
        btnSave.enabled = true;
        return;
    }
    if ([returnString isEqualToString:@"duplicate"])
    {
        [[[UIAlertView alloc] initWithTitle:@"Free Lottery" message:@"An account with that e-mail address already exists" delegate:self cancelButtonTitle:@"OK" otherButtonTitles:nil] show];
        btnSave.enabled = true;
        return;
    }
     */
    if ([returnString isEqualToString:@"badsession"])
    {
        //attempt to reconnect? or record disconnection and logout
        disconnected = true;
        [delegate logoutPost];
        [appDel setDisconnected];
       
        //stationary alert
        [[NSAlert alertWithMessageText:@"GameQ Disconnected" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"You have been disconnected from the GameQ servers, please try reconnecting!"] runModal];
        
        // mobile alert
        //[[[UIAlertView alloc] initWithTitle:@"GameQ" message:@"You were disconnected from the server, please try reconnecting!" delegate:self cancelButtonTitle:@"OK" otherButtonTitles:nil] show];
        return;
    }
    if ([returnString isEqualToString: @"no"])
    {
        //should be unreachable, disconnect the bastard!
        disconnected = true;
        [delegate logoutPost];
        [appDel setDisconnected];
        
        //statioanry alert
        [[NSAlert alertWithMessageText:@"GameQ Connection Error" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Connection error, please try again in a minute!"] runModal];
        
        // mobile alert
        //[[[UIAlertView alloc] initWithTitle:@"GameQ" message:@"Connection error, please try again in a minute" delegate:self cancelButtonTitle:@"OK" otherButtonTitles:nil] show];
    }
}

@end

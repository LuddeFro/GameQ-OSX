//
//  LVFDefinitions.h
//  GameQ-Mobile
//
//  Created by Ludvig Fröberg on 10/23/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import <Foundation/Foundation.h>

#define kGameQServerURL @"http://server.gameq.io/GameQ_Server_Code/"
#define ServerURL kGameQServerURL;
#define loginURL kGameQServerURL@"signing.php";
#define registerURL kGameQServerURL@"regging.php";
#define logoutURL kGameQServerURL@"logging.php";
#define pushURL kGameQServerURL@"push.php";
#define softPushURL kGameQServerURL@"softPush.php";
//#define updateURL kGameQServerURL@"updateDraw.php"; //mobile link
#define getSecretURL kGameQServerURL@"getSecret.php";
#define checkSecretURL kGameQServerURL@"chkSecret.php";
#define updateTokenURL kGameQServerURL@"upMacToken.php"
#define timeURL kGameQServerURL@"upTime.php"
#define updateDeviceURL kGameQServerURL@"updateDeviceName.php"
#define updatePasswordURL kGameQServerURL@"updatePassword.php"
#define updateSecretURL kGameQServerURL@"updateSecret.php"
#define versionURL kGameQServerURL@"versionControl.php"
#define monitorMeURL kGameQServerURL@"monitorMe.php"
#define checkPhonesURL kGameQServerURL@"hasPhones.php"
#define quitURL kGameQServerURL@"quitting.php"
#define reportURL kGameQServerURL@"report.php"

#define kAPPID @"GameQ"
#define kVersion @"1.0"
#define kEmail @"EmailEmail"
#define kPass @"PasswordPassword"
#define kBolIsLoggedIn @"BolIsLoggedInBolIsLoggedIn"
#define kToken @"TokenToken"
#define kDeviceID @"DeviceIDDeviceID"
#define kFirstLog @"firstLogguurs"
#define kUnique @"mfUAID"

#define URL_ABOUT @"https://www.gameQ.io/"


#define kNOGAME 0
#define kHEROES_OF_NEWERTH 1
#define kDOTA2 2
#define kCS_GO 3
#define REGISTER_URL @"https://www.gameq.com/register"
#define kOFFLINE 0 //app running, but no game
#define kONLINE 1 //game running
#define kINGAME 2 //game running and in match
#define kNOTTRACKING 3 //tracking toggled off
#define kNotRunningGameQ 4 //self explanatory

#define kINGAME_FOR_LVFSTATE 1
#define kPUSH_FOR_LVFSTATE 0

@interface LVFDefinitions : NSObject

@end

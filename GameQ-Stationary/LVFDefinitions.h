//
//  LVFDefinitions.h
//  GameQ-Mobile
//
//  Created by Ludvig Fröberg on 10/23/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import <Foundation/Foundation.h>

#define kGameQServerURL @"http://54.76.41.235/GameQ_Server_Code/"
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
#define kAPPID @"GameQ"
#define kVersion @"1.0"
#define kEmail @"EmailEmail"
#define kPass @"PasswordPassword"
#define kBolIsLoggedIn @"BolIsLoggedInBolIsLoggedIn"
#define kToken @"TokenToken"
#define kDeviceID @"DeviceIDDeviceID"
#define kFirstLog @"FirstLogguurs"
#define kUnique @"mf-U-A-I-D"

#define URL_ABOUT @"https://www.gameQ.io/"

@interface LVFDefinitions : NSObject

@end

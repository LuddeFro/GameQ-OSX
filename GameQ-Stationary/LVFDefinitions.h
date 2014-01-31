//
//  LVFDefinitions.h
//  GameQ-Mobile
//
//  Created by Ludvig Fröberg on 10/23/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import <Foundation/Foundation.h>

#define kGameQServerURL @"http://185.2.155.237/GameQ_Server_Code/"
#define ServerURL kGameQServerURL;
#define loginURL kGameQServerURL@"signing.php";
#define registerURL kGameQServerURL@"regging.php";
#define logoutURL kGameQServerURL@"logging.php";
#define pushURL kGameQServerURL@"push.php";
#define softPushURL kGameQServerURL@"softpush.php";
//#define updateURL kGameQServerURL@"updateDraw.php";
#define getSecretURL kGameQServerURL@"getSecret.php";
#define checkSecretURL kGameQServerURL@"chkSecret.php";
#define updateTokenURL kGameQServerURL@"upMacToken.php"
#define kAPPID @"GameQ"

#define URL_ABOUT @"https://www.gameQ.com/about"

@interface LVFDefinitions : NSObject

@end

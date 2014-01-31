//
//  LVFKeyChain.h
//  GameQ-Stationary
//
//  Created by Ludvig Fröberg on 29/11/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "LVFDefinitions.h"
#import "LVFDataModel.h"

@interface LVFKeyChain : NSObject

- (void) setPassword:(NSString *)pass;
- (NSString *) getPassword;
    
@end

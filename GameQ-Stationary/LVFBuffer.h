//
//  LVFBuffer.h
//  GameQ-Stationary
//
//  Created by Ludvig Fröberg on 17/01/14.
//  Copyright (c) 2014 Ludvig Fröberg. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface LVFBuffer : NSObject

- (int) bufferValue;
- (void) increment:(int)value;
- (id) initWithSize:(int)size;
- (void) clear;
@end

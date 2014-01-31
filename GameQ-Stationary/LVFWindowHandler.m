//
//  LVFWindowHandler.m
//  GameQ-Stationary
//
//  Created by LudvigFroberg on 31/01/14.
//  Copyright (c) 2014 Ludvig Fröberg. All rights reserved.
//

#import "LVFWindowHandler.h"

@implementation LVFWindowHandler

- (void)windowWillClose:(NSNotification *)notification {
    // whichever operations are needed when the
    // window is about to be closed
    [NSApp setActivationPolicy:NSApplicationActivationPolicyProhibited];
    
}
    
@end

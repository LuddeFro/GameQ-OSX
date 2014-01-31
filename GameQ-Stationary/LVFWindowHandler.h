//
//  LVFWindowHandler.h
//  GameQ-Stationary
//
//  Created by LudvigFroberg on 31/01/14.
//  Copyright (c) 2014 Ludvig Fröberg. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface LVFWindowHandler : NSWindowController <NSWindowDelegate>

    
- (void)windowWillClose:(NSNotification *)notification;
    
    
@end

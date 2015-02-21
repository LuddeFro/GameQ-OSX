//
//  main.m
//  ServerStringBuilder
//
//  Created by Ludvig Fröberg on 22/11/14.
//  Copyright (c) 2014 Ludvig Fröberg. All rights reserved.
//

#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        
        
        
        
        //temp
        NSString *monStr = @"023103250004csgo01220030005CS60P0127000280002700527005006000600007CSGameP0527000280002700527005010012000005CSERR022700028000270052700505900590002005800210010000500007CSGameP00020000050005CS60P1010010005CSERR002400100010000500007CSGameP";
        
        
        //NSString *monStr = @"monme0106udp dst portrange 11235-11335 or tcp dst port 11031 or udp src portrange 27015-28999 or udp dst port 270050303"; //prefix
        
        
        
        NSString *builder = @"";
        for (int jj = 0; jj < monStr.length; jj++) {
            int c = [monStr characterAtIndex:jj];
            c -= 3;
            builder = [NSString stringWithFormat:@"%@%c", builder, c];
        }
        
        
        NSLog(@"%@", builder);
        
        
        
        
    }
    return 0;
}

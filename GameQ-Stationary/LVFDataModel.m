//
//  LVFdataModel.m
//  GameQ-Mobile
//
//  Created by Ludvig Fröberg on 10/23/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import "LVFDataModel.h"

@implementation LVFDataModel

-(id) initWithAppDelegate:(LVFAppDelegate *)appDel
{
    self = [super init];
    if (self)
    {
        _appDelegate = appDel;
        
        _context = [_appDelegate managedObjectContext];
        NSEntityDescription *entityDescription = [NSEntityDescription entityForName:@"LoginEntity" inManagedObjectContext:_context];
        _request = [[NSFetchRequest alloc] init];
        [_request setEntity:entityDescription];
    }
    return self;
}


- (NSString *) getToken
{
    return [[NSHost currentHost] localizedName];
    NSError *error;
    NSArray *objects = [_context executeFetchRequest:_request error:&error];
    if (objects == Nil) {
        NSLog(@"Storage files not found");
    }

    
    for (NSManagedObject *oneObject in objects) {
        return [oneObject valueForKey:@"token"];
    }
    return nil;
}
- (NSString *) getEmail
{
    NSError *error;
    NSArray *objects = [_context executeFetchRequest:_request error:&error];
    if (objects == Nil) {
        NSLog(@"Storage files not found");
    }
    
    
    for (NSManagedObject *oneObject in objects) {
        return [oneObject valueForKey:@"email"];
    }
    return nil;

}
- (NSNumber *) getBolIsLoggedIn
{
    NSError *error;
    NSArray *objects = [_context executeFetchRequest:_request error:&error];
    if (objects == Nil) {
        NSLog(@"Storage files not found");
    }
    
    
    for (NSManagedObject *oneObject in objects) {
        return [oneObject valueForKey:@"bolIsLoggedIn"];
    }
    return nil;

}
- (NSString *) getDeviceID
{
    NSError *error;
    NSArray *objects = [_context executeFetchRequest:_request error:&error];
    if (objects == Nil) {
        NSLog(@"Storage files not found");
    }
    for (NSManagedObject *oneObject in objects) {
        return [oneObject valueForKey:@"deviceID"];
    }
    return nil;
    
}
- (NSString *) getPass
{
    
    NSString *string = [[NSString alloc] initWithData:[SSKeychain passwordDataForService:kAPPID account:kAPPID] encoding:NSUTF8StringEncoding];
    return  string;
    
    //LVFKeyChain *keyChain = [[LVFKeyChain alloc] init];
    //return [keyChain getPassword];
}
- (void) setDeviceID:(NSString *)devID
{
    [self setSomething:devID forField:@"deviceID"];
}
- (void) setPass:(NSString *)pass
{
    [SSKeychain setPassword:pass forService:kAPPID account:kAPPID];
    
    //LVFKeyChain *keyChain = [[LVFKeyChain alloc] init];
    //[keyChain setPassword:pass];
    
}
- (void) setToken:(NSString *)token
{
    [self setSomething:token forField:@"token"];
}
- (void) setEmail:(NSString *)email
{
    [self setSomething:email forField:@"email"];
}
- (void) setBolIsLoggedIn:(NSNumber *)isLoggedIn
{
    [self setSomething:isLoggedIn forField:@"bolIsLoggedIn"];
}
- (void) setSomething:(id)value forField:(NSString *)field
{
    NSLog(@"%@", field);
    NSManagedObject *anObject = nil;
    NSError *error;
    NSArray *objects = [_context executeFetchRequest:_request error:&error];
    if (objects == nil) {
        NSLog(@"objects == nil  ......    (error)");
        //code should be unreachable
    }
    
    if ([objects count] > 0){
        NSLog(@"for loop is called (datamodel updates shit)");
        for (int i = 0; i < objects.count; i++) {
            anObject = [objects objectAtIndex:i];
            [anObject setValue:value forKey:field];
        }
    } else {
        NSLog(@"for loop isn't called(datamodel creates shit that wasnt already there)");
        anObject = [NSEntityDescription insertNewObjectForEntityForName:@"LoginEntity" inManagedObjectContext:_context];
        [anObject setValue:value forKey:field];
    }
    [_context save:&error];
    
}
    
    /*
     - (id)initWithIdentifier: (NSString *)identifier accessGroup:(NSString *) accessGroup;
     - (void)setObject:(id)inObject forKey:(id)key;
     - (id)objectForKey:(id)key;*/
@end

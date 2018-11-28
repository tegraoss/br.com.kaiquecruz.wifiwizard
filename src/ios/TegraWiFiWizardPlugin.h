#import <Foundation/Foundation.h>
#import <Cordova/CDV.h>

@interface TegraWiFiWizardPlugin : CDVPlugin

- (void)connect:(CDVInvokedUrlCommand *)command;
- (void)saveEapConfig:(CDVInvokedUrlCommand *)command;
- (void)disconnect:(CDVInvokedUrlCommand *)command;

@end

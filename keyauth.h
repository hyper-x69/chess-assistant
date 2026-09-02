// keyauth.h
// KeyAuth license check for Chess Assistant — iOS arm64
// Drop this next to Tweak.xm. Add to Chess_FILES in Makefile.
// Network: requires outbound HTTPS. KeyAuth endpoint: keyauth.win

#import <Foundation/Foundation.h>

// ── YOUR KeyAuth credentials ──────────────────────────────────────────────────
// Fill these in from your KeyAuth dashboard → Application → Details
#define KA_NAME    @"YOUR_APP_NAME"       // Application name (exact)
#define KA_OWNERID @"YOUR_OWNERID"        // Owner ID (kDndyOKhE7)
#define KA_SECRET  @"YOUR_APP_SECRET"     // Application secret 8ee098355eb10cde94ff65301cfeb486e24e26db8d3c6a456bac2bce76c63a7b
#define KA_VERSION @"1.0"                 // Version ( 2.5.2)
// ─────────────────────────────────────────────────────────────────────────────

typedef void (^KeyAuthResult)(BOOL licensed, NSString * _Nullable message);

// ─── Internal state ──────────────────────────────────────────────────────────
static NSString *gKA_SessionToken = nil;  // set after init succeeds
static BOOL      gKA_Initialized  = NO;

// ─── Helpers ─────────────────────────────────────────────────────────────────

static NSString *ka_hwid(void) {
    // UIDevice identifierForVendor — resets on app reinstall but good enough for licensing
    return [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"unknown";
}

static NSDictionary * _Nullable ka_parseResponse(NSData *data) {
    if (!data) return nil;
    return [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
}

// ─── Step 1: Init (must call first, gets session token) ──────────────────────
static void ka_init(void (^done)(BOOL ok)) {
    NSString *hwid = ka_hwid();
    NSString *body = [NSString stringWithFormat:
        @"type=init&name=%@&ownerid=%@&secret=%@&version=%@&hash=%@",
        KA_NAME, KA_OWNERID, KA_SECRET, KA_VERSION,
        // hash field: pass empty string — KeyAuth accepts it when hash checking is off
        // If you enabled hash checking in the dashboard, compute SHA256 of your dylib here
        @""];

    NSURL *url = [NSURL URLWithString:@"https://keyauth.win/api/1.2/"];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.HTTPBody   = [body dataUsingEncoding:NSUTF8StringEncoding];
    [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];

    [[NSURLSession.sharedSession dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            NSDictionary *json = ka_parseResponse(d);
            BOOL ok = [json[@"success"] boolValue];
            if (ok) {
                gKA_SessionToken = json[@"sessionid"];
                gKA_Initialized  = YES;
            }
            dispatch_async(dispatch_get_main_queue(), ^{ done(ok); });
    }] resume];
}

// ─── Step 2: License check ────────────────────────────────────────────────────
static void ka_license(NSString *key, KeyAuthResult done) {
    if (!gKA_Initialized || !gKA_SessionToken) {
        done(NO, @"Not initialized. Check network.");
        return;
    }
    NSString *hwid = ka_hwid();
    NSString *body = [NSString stringWithFormat:
        @"type=license&key=%@&hwid=%@&sessionid=%@&name=%@&ownerid=%@",
        [key stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.URLQueryAllowedCharacterSet],
        hwid, gKA_SessionToken, KA_NAME, KA_OWNERID];

    NSURL *url = [NSURL URLWithString:@"https://keyauth.win/api/1.2/"];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.HTTPBody   = [body dataUsingEncoding:NSUTF8StringEncoding];
    [req setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];

    [[NSURLSession.sharedSession dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            NSDictionary *json = ka_parseResponse(d);
            BOOL ok = [json[@"success"] boolValue];
            NSString *msg = json[@"message"] ?: (e.localizedDescription ?: @"Unknown error");
            dispatch_async(dispatch_get_main_queue(), ^{ done(ok, msg); });
    }] resume];
}

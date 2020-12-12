/*
 * SSLBypass
 *
 * Created by EvilPenguin
 */

#import <Security/SecureTransport.h>
#include <mach-o/dyld.h>
#include <Foundation/Foundation.h>
#include <dlfcn.h>

#ifdef DEBUG
    #define DLog(FORMAT, ...) fprintf(stderr, "+[SSLBypass] %s\n", [[NSString stringWithFormat:FORMAT, ##__VA_ARGS__] UTF8String]);
#else 
    #define DLog(...) (void)0
#endif

#pragma mark - iOS 8/9

%group other_ios

static OSStatus (*original_SSLSetSessionOption)(SSLContextRef context, SSLSessionOption option, Boolean value);
static OSStatus replaced_SSLSetSessionOption(SSLContextRef context, SSLSessionOption option, Boolean value) {
    DLog(@"replaced_SSLSetSessionOption");

    if (option == kSSLSessionOptionBreakOnServerAuth) return noErr;
    else return original_SSLSetSessionOption(context, option, value);
}

static SSLContextRef (*original_SSLCreateContext) (CFAllocatorRef alloc, SSLProtocolSide protocolSide, SSLConnectionType connectionType);
static SSLContextRef replaced_SSLCreateContext(CFAllocatorRef alloc, SSLProtocolSide protocolSide, SSLConnectionType connectionType) {
    DLog(@"replaced_SSLCreateContext");

    SSLContextRef sslContext = original_SSLCreateContext(alloc, protocolSide, connectionType);
    original_SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, true);

    return sslContext;
}

static OSStatus (*original_SSLHandshake)(SSLContextRef context);
static OSStatus replaced_SSLHandshake(SSLContextRef context) {
    DLog(@"replaced_SSLHandshake");

    OSStatus result = original_SSLHandshake(context);
    if (result == errSSLServerAuthCompleted) return original_SSLHandshake(context);
    
	return result;
}

%end

#pragma mark - iOS 10

%group hook_ios_10

static OSStatus (*original_tls_helper_create_peer_trust)(void *hdsk, bool server, SecTrustRef *trustRef);
static OSStatus replaced_tls_helper_create_peer_trust(void *hdsk, bool server, SecTrustRef *trustRef) {
    DLog(@"replaced_tls_helper_create_peer_trust");
    return errSecSuccess;
}

%end

#pragma mark - iOS 13 & 12

%group hook_ios12_13

static int _verify_callback_that_does_not_validate(void *ssl, uint8_t *out_alert) {
	DLog(@"_verify_callback_that_does_not_validate");

    return 0;
}

static char *(*original_SSL_get_psk_identity)(void *ssl);
static char *replaced_SSL_get_psk_identity(void *ssl) {
	DLog(@"replaced_SSL_get_psk_identity");

    return (char *)"SSLByPass-NotRealPSK";
}

%end

#pragma mark - iOS 11

%group hook_ios_11

static OSStatus (*original_nw_tls_create_peer_trust)(void *hdsk, bool server, SecTrustRef *trustRef);
static OSStatus replaced_nw_tls_create_peer_trust(void *hdsk, bool server, SecTrustRef *trustRef) {
    DLog(@"replaced_nw_tls_create_peer_trust");
    return errSecSuccess;
}

%end


#pragma mark - iOS 12

%group hook_ios_12

static void (*original_SSL_CTX_set_custom_verify)(void *ctx, int mode, int (*callback)(void *ssl, uint8_t *out_alert));
static void replaced_SSL_CTX_set_custom_verify(void *ctx, int mode, int (*callback)(void *ssl, uint8_t *out_alert)) {
	DLog(@"replaced_SSL_CTX_set_custom_verify");

    original_SSL_CTX_set_custom_verify(ctx, 0, _verify_callback_that_does_not_validate);
}

%end

#pragma mark - iOS 13

%group hook_ios_13

static void (*original_SSL_set_custom_verify)(void *ssl, int mode, int (*callback)(void *ssl, uint8_t *out_alert));
static void replaced_SSL_set_custom_verify(void *ssl, int mode, int (*callback)(void *ssl, uint8_t *out_alert)) {
	DLog(@"replaced_SSL_set_custom_verify");

    original_SSL_set_custom_verify(ssl, 0, _verify_callback_that_does_not_validate);
}

%end


#pragma mark - Constructor

%ctor {
	@autoreleasepool {
        DLog(@"Enabled");

        NSProcessInfo *processInfo = [NSProcessInfo processInfo];
        DLog(@"%@", processInfo.operatingSystemVersionString);

        BOOL isiOS13 = [processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){13, 0, 0}];
        BOOL isiOS12 = [processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){12, 0, 0}]; 

        if (isiOS13 || isiOS12) {
            void *boringssl_handle = dlopen("/usr/lib/libboringssl.dylib", RTLD_NOW);

            %init(hook_ios12_13);
            void *SSL_get_psk_identity = dlsym(boringssl_handle, "SSL_get_psk_identity");
            if (SSL_get_psk_identity) {
                DLog(@"SSL_get_psk_identity %p", SSL_get_psk_identity);
                MSHookFunction((void *)SSL_get_psk_identity, (void *)replaced_SSL_get_psk_identity, (void **)&original_SSL_get_psk_identity);
            }

            if (isiOS13) {
                %init(hook_ios_13);

                void *SSL_set_custom_verify = dlsym(boringssl_handle, "SSL_set_custom_verify");
                if (SSL_set_custom_verify) {
                    DLog(@"SSL_set_custom_verify %p", SSL_set_custom_verify);
                    MSHookFunction((void *)SSL_set_custom_verify, (void *)replaced_SSL_set_custom_verify, (void **)&original_SSL_set_custom_verify);
                }
            }
            else if (isiOS12) {
                %init(hook_ios_12);

                void *SSL_CTX_set_custom_verify = dlsym(boringssl_handle, "SSL_CTX_set_custom_verify");
                if (SSL_CTX_set_custom_verify) {
                    DLog(@"SSL_CTX_set_custom_verify %p", SSL_CTX_set_custom_verify);
                    MSHookFunction((void *)SSL_CTX_set_custom_verify, (void *)replaced_SSL_CTX_set_custom_verify, (void **)&original_SSL_CTX_set_custom_verify);
                }
            }
        }
        else if ([processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){11, 0, 0}]) {
            %init(hook_ios_11);

            void *libnetwork = dlopen("/usr/lib/libnetwork.dylib", RTLD_NOW);
            void *nw_tls_create_peer_trust = dlsym(libnetwork, "nw_tls_create_peer_trust");
            if (nw_tls_create_peer_trust) {
                DLog(@"nw_tls_create_peer_trust %p", nw_tls_create_peer_trust);
                MSHookFunction((void *)nw_tls_create_peer_trust, (void *)replaced_nw_tls_create_peer_trust, (void **)&original_nw_tls_create_peer_trust);
            }
        }
        else if ([processInfo isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion){10, 0, 0}]) {
            %init(hook_ios_10);

            void *tls_helper_create_peer_trust = dlsym(RTLD_DEFAULT, "tls_helper_create_peer_trust");
            DLog(@"tls_helper_create_peer_trust %p", tls_helper_create_peer_trust);
            MSHookFunction((void *)tls_helper_create_peer_trust, (void *)replaced_tls_helper_create_peer_trust, (void **)&original_tls_helper_create_peer_trust);
        }
        else {
            %init(other_ios);

            MSHookFunction((void *)SSLHandshake, (void *)replaced_SSLHandshake, (void **)&original_SSLHandshake);
            MSHookFunction((void *)SSLSetSessionOption, (void *)replaced_SSLSetSessionOption, (void **)&original_SSLSetSessionOption);
            MSHookFunction((void *)SSLCreateContext, (void *)replaced_SSLCreateContext, (void **)&original_SSLCreateContext);
        }
	}
}
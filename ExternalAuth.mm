#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <QuartzCore/QuartzCore.h>
#import <ImageIO/ImageIO.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <mach-o/getsect.h>
#import <mach-o/loader.h>
#import <math.h>
#import <stdlib.h>

// ============================================================
// EXTERNAL AUTH V6 — SERVER LOCKED / HWID + SIGNED CHALLENGE
// Backend:
//   POST /api/security/hwid/challenge
//   POST /api/security/hwid/verify
//   POST /api/security/session/heartbeat
//
// UI:
//   GIF -> "Digite sua key para continuar"
//   KEY
//   HWID + Detectar
//   Entrar
//
// Observacao: iOS nao fornece serial/UDID de hardware para apps comuns.
// O "HWID" abaixo e um identificador de app/dispositivo derivado do IDFV,
// modelo de hardware e persistido no Keychain para estabilidade.
// ============================================================

static NSTimeInterval const EARequestTimeout = 15.0;
static NSTimeInterval const EARevalidateInterval = 15.0;
static NSTimeInterval const EAHeartbeatGraceInterval = 45.0;
static NSString * const EAKeychainService = @"app.external.auth";
static NSString * const EAKeyAccount = @"license-key";
static NSString * const EAHWIDAccount = @"hwid-v1";
static NSString * const EABuildMarker = @"EA-HWID-V6-SERVER-LOCKED";
static NSString * const EADeviceSigningKeyTag = @"app.external.auth.device-signing-v1";

static NSString *EAAPIBaseURL(void) {
    return @"https://externalconfig.shardweb.app";
}

static NSString *EAHexSHA256(NSString *input) {
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding];
    if (!data) return @"";

    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);

    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02X", digest[i]];
    }
    return hex;
}


static NSString *EAHexSHA256Data(NSData *data) {
    if (data.length == 0) return @"";

    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);

    NSMutableString *hex =
        [NSMutableString stringWithCapacity:
            CC_SHA256_DIGEST_LENGTH * 2];

    for (
        NSUInteger i = 0;
        i < CC_SHA256_DIGEST_LENGTH;
        i++
    ) {
        [hex appendFormat:@"%02X", digest[i]];
    }

    return hex;
}

static NSString *EASelfDylibSHA256(void) {
    static NSString *cached = nil;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        Dl_info info;

        if (
            dladdr(
                (const void *)&EASelfDylibSHA256,
                &info
            ) == 0 ||
            !info.dli_fname
        ) {
            cached = @"";
            return;
        }

        NSString *path =
            [NSString stringWithUTF8String:
                info.dli_fname];

        NSData *data =
            path.length
                ? [NSData dataWithContentsOfFile:path]
                : nil;

        cached =
            data.length
                ? EAHexSHA256Data(data)
                : @"";
    });

    return cached ?: @"";
}

static NSString *EAHardwareModel(void) {
    size_t size = 0;
    sysctlbyname("hw.machine", NULL, &size, NULL, 0);
    if (size == 0) return UIDevice.currentDevice.model ?: @"iPhone";

    char *machine = (char *)calloc(1, size);
    if (!machine) return UIDevice.currentDevice.model ?: @"iPhone";

    sysctlbyname("hw.machine", machine, &size, NULL, 0);
    NSString *result = [NSString stringWithUTF8String:machine] ?: @"iPhone";
    free(machine);
    return result;
}

static NSData *EAEmbeddedGIFData(void) {
#if __LP64__
    Dl_info info;
    if (dladdr((const void *)&EAEmbeddedGIFData, &info) == 0 || !info.dli_fbase) {
        return nil;
    }

    const struct mach_header_64 *header = (const struct mach_header_64 *)info.dli_fbase;
    unsigned long size = 0;
    const uint8_t *bytes = getsectiondata(header, "__DATA", "__eaicon", &size);
    if (!bytes || size == 0) return nil;

    return [NSData dataWithBytes:bytes length:(NSUInteger)size];
#else
    return nil;
#endif
}

@interface ExternalAuthManager : NSObject <UITextFieldDelegate, NSURLSessionDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UIViewController *controller;
@property (nonatomic, strong) UIImageView *gifCurrentView;
@property (nonatomic, strong) UIImageView *gifNextView;
@property (nonatomic, strong) NSArray<UIImage *> *gifFrames;
@property (nonatomic, strong) CADisplayLink *gifDisplayLink;
@property (nonatomic, assign) CFTimeInterval gifStartTimestamp;
@property (nonatomic, assign) NSTimeInterval gifFrameDuration;
@property (nonatomic, assign) NSInteger gifRenderedIndex;

@property (nonatomic, strong) UITextField *keyField;
@property (nonatomic, strong) UITextField *hwidField;
@property (nonatomic, strong) UIButton *detectButton;
@property (nonatomic, strong) UIButton *enterButton;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;

@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, strong) NSTimer *revalidateTimer;
@property (nonatomic, copy) NSString *validatedKey;
@property (nonatomic, copy) NSString *validatedHWID;
@property (nonatomic, assign) BOOL started;
@property (nonatomic, assign) BOOL unlocked;
@property (nonatomic, assign) BOOL requestInFlight;
@property (nonatomic, copy) NSString *securitySessionToken;
@property (nonatomic, copy) NSString *securitySessionExpiresAt;
@property (nonatomic, copy) NSString *heartbeatNonce;
@property (nonatomic, assign) CFTimeInterval lastServerSuccess;

+ (instancetype)shared;
- (void)start;
@end

@implementation ExternalAuthManager

+ (instancetype)shared {
    static ExternalAuthManager *manager;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        manager = [ExternalAuthManager new];
    });
    return manager;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [self.revalidateTimer invalidate];
    [self.gifDisplayLink invalidate];
    [self.session invalidateAndCancel];
}

#pragma mark - Keychain

- (NSMutableDictionary *)keychainQuery:(NSString *)account {
    return [@{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: EAKeychainService,
        (__bridge id)kSecAttrAccount: account
    } mutableCopy];
}

- (NSString *)keychainString:(NSString *)account {
    NSMutableDictionary *query = [self keychainQuery:account];
    query[(__bridge id)kSecReturnData] = @YES;
    query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status != errSecSuccess || !result) {
        if (result) CFRelease(result);
        return nil;
    }

    NSData *data = CFBridgingRelease(result);
    if (![data isKindOfClass:[NSData class]]) return nil;
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (void)setKeychainString:(NSString *)value account:(NSString *)account {
    NSMutableDictionary *query = [self keychainQuery:account];
    SecItemDelete((__bridge CFDictionaryRef)query);

    if (value.length == 0) return;

    NSMutableDictionary *item = [query mutableCopy];
    item[(__bridge id)kSecValueData] = [value dataUsingEncoding:NSUTF8StringEncoding];
    item[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    SecItemAdd((__bridge CFDictionaryRef)item, NULL);
}

- (NSString *)normalizedKey:(NSString *)value {
    if (![value isKindOfClass:[NSString class]]) return @"";
    NSString *trimmed = [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    return trimmed.uppercaseString;
}

#pragma mark - Device signing key

- (NSData *)deviceSigningKeyTagData {
    return [
        EADeviceSigningKeyTag
        dataUsingEncoding:NSUTF8StringEncoding
    ];
}

- (SecKeyRef)copyExistingDevicePrivateKey {
    NSDictionary *query = @{
        (__bridge id)kSecClass:
            (__bridge id)kSecClassKey,
        (__bridge id)kSecAttrApplicationTag:
            [self deviceSigningKeyTagData],
        (__bridge id)kSecAttrKeyType:
            (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecReturnRef:
            @YES
    };

    CFTypeRef result = NULL;

    OSStatus status =
        SecItemCopyMatching(
            (__bridge CFDictionaryRef)query,
            &result
        );

    if (
        status != errSecSuccess ||
        !result
    ) {
        if (result) CFRelease(result);
        return NULL;
    }

    return (SecKeyRef)result;
}

- (SecKeyRef)copyOrCreateDevicePrivateKey {
    SecKeyRef existing =
        [self copyExistingDevicePrivateKey];

    if (existing) {
        return existing;
    }

    NSDictionary *privateAttributes = @{
        (__bridge id)kSecAttrIsPermanent:
            @YES,
        (__bridge id)kSecAttrApplicationTag:
            [self deviceSigningKeyTagData],
        (__bridge id)kSecAttrAccessible:
            (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    };

    NSMutableDictionary *attributes =
        [@{
            (__bridge id)kSecAttrKeyType:
                (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
            (__bridge id)kSecAttrKeySizeInBits:
                @256,
            (__bridge id)kSecPrivateKeyAttrs:
                privateAttributes
        } mutableCopy];

    CFErrorRef error = NULL;

    // Tenta Secure Enclave primeiro. Se o contexto de assinatura
    // nao aceitar, cai automaticamente para uma EC P-256 normal
    // mantida no Keychain deste aparelho.
    if (@available(iOS 10.0, *)) {
        attributes[
            (__bridge id)kSecAttrTokenID
        ] = (__bridge id)kSecAttrTokenIDSecureEnclave;
    }

    SecKeyRef key =
        SecKeyCreateRandomKey(
            (__bridge CFDictionaryRef)attributes,
            &error
        );

    if (!key) {
        if (error) {
            CFRelease(error);
            error = NULL;
        }

        [attributes removeObjectForKey:
            (__bridge id)kSecAttrTokenID];

        key =
            SecKeyCreateRandomKey(
                (__bridge CFDictionaryRef)attributes,
                &error
            );
    }

    if (error) {
        CFRelease(error);
    }

    return key;
}

- (NSString *)devicePublicKeyBase64 {
    SecKeyRef privateKey =
        [self copyOrCreateDevicePrivateKey];

    if (!privateKey) {
        return nil;
    }

    SecKeyRef publicKey =
        SecKeyCopyPublicKey(
            privateKey
        );

    CFRelease(privateKey);

    if (!publicKey) {
        return nil;
    }

    CFErrorRef error = NULL;

    CFDataRef external =
        SecKeyCopyExternalRepresentation(
            publicKey,
            &error
        );

    CFRelease(publicKey);

    if (error) {
        CFRelease(error);
    }

    if (!external) {
        return nil;
    }

    NSData *data =
        CFBridgingRelease(
            external
        );

    // P-256 publica em formato ANSI X9.63:
    // 0x04 || X(32) || Y(32)
    if (
        data.length != 65 ||
        ((const uint8_t *)data.bytes)[0] != 0x04
    ) {
        return nil;
    }

    return [
        data
        base64EncodedStringWithOptions:0
    ];
}

- (NSString *)signatureForMessage:(NSString *)message {
    NSData *data =
        [
            message ?: @""
            dataUsingEncoding:NSUTF8StringEncoding
        ];

    if (data.length == 0) {
        return nil;
    }

    SecKeyRef privateKey =
        [self copyOrCreateDevicePrivateKey];

    if (!privateKey) {
        return nil;
    }

    SecKeyAlgorithm algorithm =
        kSecKeyAlgorithmECDSASignatureMessageX962SHA256;

    if (
        !SecKeyIsAlgorithmSupported(
            privateKey,
            kSecKeyOperationTypeSign,
            algorithm
        )
    ) {
        CFRelease(privateKey);
        return nil;
    }

    CFErrorRef error = NULL;

    CFDataRef signature =
        SecKeyCreateSignature(
            privateKey,
            algorithm,
            (__bridge CFDataRef)data,
            &error
        );

    CFRelease(privateKey);

    if (error) {
        CFRelease(error);
    }

    if (!signature) {
        return nil;
    }

    NSData *signatureData =
        CFBridgingRelease(
            signature
        );

    return [
        signatureData
        base64EncodedStringWithOptions:0
    ];
}

#pragma mark - HWID

- (NSString *)detectHWID {
    NSString *saved = [self keychainString:EAHWIDAccount];
    if (saved.length >= 8) return saved.uppercaseString;

    NSString *idfv = UIDevice.currentDevice.identifierForVendor.UUIDString;
    if (idfv.length == 0) {
        idfv = NSUUID.UUID.UUIDString;
    }

    NSString *hardware = EAHardwareModel();
    NSString *seed = [NSString stringWithFormat:@"%@|%@|EXTERNAL-HWID-V1", idfv, hardware];
    NSString *digest = EAHexSHA256(seed);
    if (digest.length == 0) return nil;

    NSString *hwid = [@"HWID-" stringByAppendingString:digest];
    [self setKeychainString:hwid account:EAHWIDAccount];
    return hwid;
}

#pragma mark - Embedded GIF / 50 FPS renderer

- (void)prepareGIF {
    NSData *data = EAEmbeddedGIFData();
    if (data.length == 0) return;

    CGImageSourceRef source = CGImageSourceCreateWithData((__bridge CFDataRef)data, NULL);
    if (!source) return;

    size_t count = CGImageSourceGetCount(source);
    if (count == 0) {
        CFRelease(source);
        return;
    }

    NSMutableArray<UIImage *> *frames = [NSMutableArray arrayWithCapacity:count];
    NSTimeInterval totalDuration = 0.0;

    NSDictionary *thumbOptions = @{
        (__bridge NSString *)kCGImageSourceCreateThumbnailFromImageAlways: @YES,
        (__bridge NSString *)kCGImageSourceCreateThumbnailWithTransform: @YES,
        (__bridge NSString *)kCGImageSourceShouldCacheImmediately: @YES,
        (__bridge NSString *)kCGImageSourceThumbnailMaxPixelSize: @230
    };

    for (size_t i = 0; i < count; i++) {
        CGImageRef cg = CGImageSourceCreateThumbnailAtIndex(source, i, (__bridge CFDictionaryRef)thumbOptions);
        if (cg) {
            UIImage *image = [UIImage imageWithCGImage:cg scale:UIScreen.mainScreen.scale orientation:UIImageOrientationUp];
            if (image) [frames addObject:image];
            CGImageRelease(cg);
        }

        NSTimeInterval delay = 0.05;
        CFDictionaryRef propsRef = CGImageSourceCopyPropertiesAtIndex(source, i, NULL);
        if (propsRef) {
            NSDictionary *props = CFBridgingRelease(propsRef);
            NSDictionary *gif = props[(__bridge NSString *)kCGImagePropertyGIFDictionary];
            NSNumber *unclamped = gif[(__bridge NSString *)kCGImagePropertyGIFUnclampedDelayTime];
            NSNumber *clamped = gif[(__bridge NSString *)kCGImagePropertyGIFDelayTime];
            NSNumber *duration = unclamped ?: clamped;
            if (duration.doubleValue > 0.001) delay = duration.doubleValue;
        }
        totalDuration += delay;
    }

    CFRelease(source);

    if (frames.count == 0) return;

    self.gifFrames = frames;
    self.gifFrameDuration = totalDuration > 0.0
        ? totalDuration / (NSTimeInterval)frames.count
        : 0.05;

    self.gifCurrentView.image = frames.firstObject;
    self.gifNextView.image = frames.count > 1 ? frames[1] : frames.firstObject;
    self.gifCurrentView.alpha = 1.0;
    self.gifNextView.alpha = 0.0;
    self.gifRenderedIndex = -1;

    [self.gifDisplayLink invalidate];
    self.gifDisplayLink = [CADisplayLink displayLinkWithTarget:self selector:@selector(renderGIF:)];
    self.gifDisplayLink.preferredFramesPerSecond = 50;
    if (@available(iOS 15.0, *)) {
        self.gifDisplayLink.preferredFrameRateRange = CAFrameRateRangeMake(50.0, 50.0, 50.0);
    }
    [self.gifDisplayLink addToRunLoop:NSRunLoop.mainRunLoop forMode:NSRunLoopCommonModes];
}

- (void)renderGIF:(CADisplayLink *)link {
    NSUInteger count = self.gifFrames.count;
    if (count == 0 || self.gifFrameDuration <= 0.0) return;

    if (self.gifStartTimestamp <= 0.0) {
        self.gifStartTimestamp = link.timestamp;
    }

    CFTimeInterval elapsed = link.timestamp - self.gifStartTimestamp;
    NSTimeInterval totalDuration = self.gifFrameDuration * (NSTimeInterval)count;
    if (totalDuration <= 0.0) return;

    double normalizedTime = fmod(elapsed, totalDuration);
    double sourcePosition = normalizedTime / self.gifFrameDuration;
    NSInteger currentIndex = ((NSInteger)floor(sourcePosition)) % (NSInteger)count;
    NSInteger nextIndex = (currentIndex + 1) % (NSInteger)count;
    CGFloat blend = (CGFloat)(sourcePosition - floor(sourcePosition));

    if (currentIndex != self.gifRenderedIndex) {
        self.gifCurrentView.image = self.gifFrames[(NSUInteger)currentIndex];
        self.gifNextView.image = self.gifFrames[(NSUInteger)nextIndex];
        self.gifRenderedIndex = currentIndex;
    }

    // O GIF original tem frames de ~50 ms. Em vez de acelerar o loop,
    // interpolamos visualmente entre os frames num render loop de 50 Hz.
    self.gifCurrentView.alpha = 1.0 - blend;
    self.gifNextView.alpha = blend;
}

#pragma mark - Window / UI

- (UIWindowScene *)activeScene API_AVAILABLE(ios(13.0)) {
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (scene.activationState == UISceneActivationStateForegroundActive &&
            [scene isKindOfClass:UIWindowScene.class]) {
            return (UIWindowScene *)scene;
        }
    }

    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if ([scene isKindOfClass:UIWindowScene.class]) return (UIWindowScene *)scene;
    }

    return nil;
}

- (UIView *)darkFieldContainer {
    UIView *view = [UIView new];
    view.translatesAutoresizingMaskIntoConstraints = NO;
    view.backgroundColor = [UIColor colorWithWhite:0.055 alpha:1.0];
    view.layer.cornerRadius = 16.0;
    view.layer.cornerCurve = kCACornerCurveContinuous;
    view.layer.borderWidth = 1.0;
    view.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.17].CGColor;
    return view;
}

- (void)buildUI {
    if (self.window) return;

    CGRect bounds = UIScreen.mainScreen.bounds;
    if (@available(iOS 13.0, *)) {
        UIWindowScene *scene = [self activeScene];
        self.window = scene
            ? [[UIWindow alloc] initWithWindowScene:scene]
            : [[UIWindow alloc] initWithFrame:bounds];
    } else {
        self.window = [[UIWindow alloc] initWithFrame:bounds];
    }

    self.window.windowLevel = UIWindowLevelAlert + 2000.0;
    self.window.backgroundColor = UIColor.blackColor;

    self.controller = [UIViewController new];
    self.controller.view.backgroundColor = UIColor.blackColor;
    self.window.rootViewController = self.controller;

    UIView *root = self.controller.view;
    root.backgroundColor = UIColor.blackColor;

    UIView *content = [UIView new];
    content.translatesAutoresizingMaskIntoConstraints = NO;
    [root addSubview:content];

    UIView *gifContainer = [UIView new];
    gifContainer.translatesAutoresizingMaskIntoConstraints = NO;
    gifContainer.backgroundColor = UIColor.clearColor;
    gifContainer.clipsToBounds = YES;
    [content addSubview:gifContainer];

    self.gifCurrentView = [UIImageView new];
    self.gifCurrentView.translatesAutoresizingMaskIntoConstraints = NO;
    self.gifCurrentView.contentMode = UIViewContentModeScaleAspectFit;
    [gifContainer addSubview:self.gifCurrentView];

    self.gifNextView = [UIImageView new];
    self.gifNextView.translatesAutoresizingMaskIntoConstraints = NO;
    self.gifNextView.contentMode = UIViewContentModeScaleAspectFit;
    self.gifNextView.alpha = 0.0;
    [gifContainer addSubview:self.gifNextView];

    UILabel *subtitle = [UILabel new];
    subtitle.translatesAutoresizingMaskIntoConstraints = NO;
    subtitle.text = @"Digite sua key para continuar";
    subtitle.textAlignment = NSTextAlignmentCenter;
    subtitle.textColor = [UIColor colorWithWhite:0.67 alpha:1.0];
    subtitle.font = [UIFont systemFontOfSize:16.0 weight:UIFontWeightRegular];
    [content addSubview:subtitle];

    UIView *keyBox = [self darkFieldContainer];
    [content addSubview:keyBox];

    self.keyField = [UITextField new];
    self.keyField.translatesAutoresizingMaskIntoConstraints = NO;
    self.keyField.placeholder = @"KEY";
    self.keyField.attributedPlaceholder = [[NSAttributedString alloc]
        initWithString:@"KEY"
        attributes:@{ NSForegroundColorAttributeName: [UIColor colorWithWhite:0.48 alpha:1.0] }];
    self.keyField.textColor = UIColor.whiteColor;
    self.keyField.tintColor = UIColor.whiteColor;
    self.keyField.font = [UIFont systemFontOfSize:16.0 weight:UIFontWeightRegular];
    self.keyField.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    self.keyField.autocorrectionType = UITextAutocorrectionTypeNo;
    self.keyField.spellCheckingType = UITextSpellCheckingTypeNo;
    self.keyField.clearButtonMode = UITextFieldViewModeWhileEditing;
    self.keyField.returnKeyType = UIReturnKeyDone;
    self.keyField.keyboardAppearance = UIKeyboardAppearanceDark;
    self.keyField.delegate = self;
    [keyBox addSubview:self.keyField];

    UIView *hwidBox = [self darkFieldContainer];
    [content addSubview:hwidBox];

    self.hwidField = [UITextField new];
    self.hwidField.translatesAutoresizingMaskIntoConstraints = NO;
    self.hwidField.placeholder = @"HWID";
    self.hwidField.attributedPlaceholder = [[NSAttributedString alloc]
        initWithString:@"HWID"
        attributes:@{ NSForegroundColorAttributeName: [UIColor colorWithWhite:0.48 alpha:1.0] }];
    self.hwidField.textColor = [UIColor colorWithWhite:0.88 alpha:1.0];
    self.hwidField.font = [UIFont monospacedSystemFontOfSize:11.0 weight:UIFontWeightRegular];
    self.hwidField.adjustsFontSizeToFitWidth = YES;
    self.hwidField.minimumFontSize = 7.0;
    self.hwidField.userInteractionEnabled = NO;
    [hwidBox addSubview:self.hwidField];

    self.detectButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.detectButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.detectButton setTitle:@"Detectar" forState:UIControlStateNormal];
    [self.detectButton setTitleColor:[UIColor colorWithWhite:0.88 alpha:1.0] forState:UIControlStateNormal];
    self.detectButton.titleLabel.font = [UIFont systemFontOfSize:14.0 weight:UIFontWeightSemibold];
    self.detectButton.backgroundColor = [UIColor colorWithWhite:0.055 alpha:1.0];
    self.detectButton.layer.cornerRadius = 16.0;
    self.detectButton.layer.cornerCurve = kCACornerCurveContinuous;
    self.detectButton.layer.borderWidth = 1.0;
    self.detectButton.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.17].CGColor;
    [self.detectButton addTarget:self action:@selector(detectTapped) forControlEvents:UIControlEventTouchUpInside];
    [content addSubview:self.detectButton];

    self.enterButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.enterButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.enterButton setTitle:@"Entrar" forState:UIControlStateNormal];
    [self.enterButton setTitleColor:UIColor.blackColor forState:UIControlStateNormal];
    self.enterButton.titleLabel.font = [UIFont systemFontOfSize:16.0 weight:UIFontWeightBold];
    self.enterButton.backgroundColor = UIColor.whiteColor;
    self.enterButton.layer.cornerRadius = 16.0;
    self.enterButton.layer.cornerCurve = kCACornerCurveContinuous;
    [self.enterButton addTarget:self action:@selector(enterTapped) forControlEvents:UIControlEventTouchUpInside];
    [content addSubview:self.enterButton];

    self.spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    self.spinner.translatesAutoresizingMaskIntoConstraints = NO;
    self.spinner.color = UIColor.blackColor;
    self.spinner.hidesWhenStopped = YES;
    [self.enterButton addSubview:self.spinner];

    self.statusLabel = [UILabel new];
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 3;
    self.statusLabel.font = [UIFont systemFontOfSize:11.5 weight:UIFontWeightMedium];
    self.statusLabel.textColor = [UIColor colorWithWhite:0.62 alpha:1.0];
    self.statusLabel.text = @"";
    [content addSubview:self.statusLabel];

    NSLayoutConstraint *responsiveWidth =
        [content.widthAnchor constraintEqualToAnchor:root.widthAnchor multiplier:0.86];
    responsiveWidth.priority = UILayoutPriorityDefaultHigh;

    [NSLayoutConstraint activateConstraints:@[
        [content.centerXAnchor constraintEqualToAnchor:root.centerXAnchor],
        [content.centerYAnchor constraintEqualToAnchor:root.centerYAnchor constant:-96.0],
        [content.leadingAnchor constraintGreaterThanOrEqualToAnchor:root.safeAreaLayoutGuide.leadingAnchor constant:24.0],
        [content.trailingAnchor constraintLessThanOrEqualToAnchor:root.safeAreaLayoutGuide.trailingAnchor constant:-24.0],
        [content.widthAnchor constraintLessThanOrEqualToConstant:360.0],
        responsiveWidth,

        [gifContainer.topAnchor constraintEqualToAnchor:content.topAnchor],
        [gifContainer.centerXAnchor constraintEqualToAnchor:content.centerXAnchor],
        [gifContainer.widthAnchor constraintEqualToConstant:170.0],
        [gifContainer.heightAnchor constraintEqualToConstant:150.0],

        [self.gifCurrentView.leadingAnchor constraintEqualToAnchor:gifContainer.leadingAnchor],
        [self.gifCurrentView.trailingAnchor constraintEqualToAnchor:gifContainer.trailingAnchor],
        [self.gifCurrentView.topAnchor constraintEqualToAnchor:gifContainer.topAnchor],
        [self.gifCurrentView.bottomAnchor constraintEqualToAnchor:gifContainer.bottomAnchor],

        [self.gifNextView.leadingAnchor constraintEqualToAnchor:gifContainer.leadingAnchor],
        [self.gifNextView.trailingAnchor constraintEqualToAnchor:gifContainer.trailingAnchor],
        [self.gifNextView.topAnchor constraintEqualToAnchor:gifContainer.topAnchor],
        [self.gifNextView.bottomAnchor constraintEqualToAnchor:gifContainer.bottomAnchor],

        [subtitle.topAnchor constraintEqualToAnchor:gifContainer.bottomAnchor constant:18.0],
        [subtitle.leadingAnchor constraintEqualToAnchor:content.leadingAnchor],
        [subtitle.trailingAnchor constraintEqualToAnchor:content.trailingAnchor],

        [keyBox.topAnchor constraintEqualToAnchor:subtitle.bottomAnchor constant:24.0],
        [keyBox.leadingAnchor constraintEqualToAnchor:content.leadingAnchor],
        [keyBox.trailingAnchor constraintEqualToAnchor:content.trailingAnchor],
        [keyBox.heightAnchor constraintEqualToConstant:60.0],

        [self.keyField.leadingAnchor constraintEqualToAnchor:keyBox.leadingAnchor constant:18.0],
        [self.keyField.trailingAnchor constraintEqualToAnchor:keyBox.trailingAnchor constant:-12.0],
        [self.keyField.topAnchor constraintEqualToAnchor:keyBox.topAnchor],
        [self.keyField.bottomAnchor constraintEqualToAnchor:keyBox.bottomAnchor],

        [hwidBox.topAnchor constraintEqualToAnchor:keyBox.bottomAnchor constant:14.0],
        [hwidBox.leadingAnchor constraintEqualToAnchor:content.leadingAnchor],
        [hwidBox.heightAnchor constraintEqualToConstant:58.0],

        [self.detectButton.leadingAnchor constraintEqualToAnchor:hwidBox.trailingAnchor constant:10.0],
        [self.detectButton.trailingAnchor constraintEqualToAnchor:content.trailingAnchor],
        [self.detectButton.centerYAnchor constraintEqualToAnchor:hwidBox.centerYAnchor],
        [self.detectButton.widthAnchor constraintEqualToConstant:104.0],
        [self.detectButton.heightAnchor constraintEqualToAnchor:hwidBox.heightAnchor],

        [self.hwidField.leadingAnchor constraintEqualToAnchor:hwidBox.leadingAnchor constant:16.0],
        [self.hwidField.trailingAnchor constraintEqualToAnchor:hwidBox.trailingAnchor constant:-12.0],
        [self.hwidField.topAnchor constraintEqualToAnchor:hwidBox.topAnchor],
        [self.hwidField.bottomAnchor constraintEqualToAnchor:hwidBox.bottomAnchor],

        [self.enterButton.topAnchor constraintEqualToAnchor:hwidBox.bottomAnchor constant:22.0],
        [self.enterButton.leadingAnchor constraintEqualToAnchor:content.leadingAnchor],
        [self.enterButton.trailingAnchor constraintEqualToAnchor:content.trailingAnchor],
        [self.enterButton.heightAnchor constraintEqualToConstant:62.0],

        [self.spinner.centerXAnchor constraintEqualToAnchor:self.enterButton.centerXAnchor],
        [self.spinner.centerYAnchor constraintEqualToAnchor:self.enterButton.centerYAnchor],

        [self.statusLabel.topAnchor constraintEqualToAnchor:self.enterButton.bottomAnchor constant:13.0],
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:content.leadingAnchor constant:4.0],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:content.trailingAnchor constant:-4.0],
        [self.statusLabel.bottomAnchor constraintEqualToAnchor:content.bottomAnchor]
    ]];

    [self prepareGIF];
}

- (void)showWindow {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.window.hidden = NO;
        self.window.alpha = 1.0;
        [self.window makeKeyAndVisible];
    });
}

- (void)hideWindow {
    dispatch_async(dispatch_get_main_queue(), ^{
        [UIView animateWithDuration:0.20 animations:^{
            self.window.alpha = 0.0;
        } completion:^(BOOL finished) {
            self.window.hidden = YES;
            self.window.alpha = 1.0;
        }];
    });
}

- (void)setBusy:(BOOL)busy {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.requestInFlight = busy;
        self.enterButton.enabled = !busy;
        self.detectButton.enabled = !busy;
        self.keyField.enabled = !busy;
        self.enterButton.alpha = busy ? 0.86 : 1.0;

        if (busy) {
            [self.spinner startAnimating];
            [self.enterButton setTitle:@"" forState:UIControlStateNormal];
        } else {
            [self.spinner stopAnimating];
            [self.enterButton setTitle:@"Entrar" forState:UIControlStateNormal];
        }
    });
}

- (void)setStatus:(NSString *)message error:(BOOL)error maintenance:(BOOL)maintenance {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.statusLabel.text = message ?: @"";
        if (maintenance) {
            self.statusLabel.textColor = [UIColor colorWithRed:1.0 green:0.69 blue:0.35 alpha:1.0];
        } else if (error) {
            self.statusLabel.textColor = [UIColor colorWithRed:1.0 green:0.38 blue:0.42 alpha:1.0];
        } else {
            self.statusLabel.textColor = [UIColor colorWithWhite:0.65 alpha:1.0];
        }
    });
}

#pragma mark - JSON / HTTP

- (NSString *)jsonString:(NSDictionary *)json key:(NSString *)key {
    id value = json[key];
    return [value isKindOfClass:NSString.class] ? (NSString *)value : nil;
}

- (BOOL)jsonBool:(NSDictionary *)json key:(NSString *)key defaultValue:(BOOL)defaultValue {
    id value = json[key];
    return [value respondsToSelector:@selector(boolValue)] ? [value boolValue] : defaultValue;
}

- (void)postPath:(NSString *)path
              body:(NSDictionary *)body
     authorization:(NSString *)authorization
        completion:(void (^)(NSInteger, NSDictionary *, NSError *))completion {

    NSURL *url =
        [NSURL URLWithString:
            [EAAPIBaseURL()
                stringByAppendingString:path]];

    if (!url) {
        NSError *error =
            [NSError errorWithDomain:@"ExternalAuth"
                                code:-1
                            userInfo:@{
            NSLocalizedDescriptionKey:
                @"URL inválida"
        }];

        dispatch_async(
            dispatch_get_main_queue(),
            ^{
                completion(
                    0,
                    nil,
                    error
                );
            }
        );
        return;
    }

    NSError *jsonError = nil;

    NSData *bodyData =
        [NSJSONSerialization
            dataWithJSONObject:
                body ?: @{}
            options:0
            error:&jsonError];

    if (!bodyData || jsonError) {
        dispatch_async(
            dispatch_get_main_queue(),
            ^{
                completion(
                    0,
                    nil,
                    jsonError
                );
            }
        );
        return;
    }

    NSMutableURLRequest *request =
        [NSMutableURLRequest
            requestWithURL:url];

    request.HTTPMethod = @"POST";
    request.timeoutInterval =
        EARequestTimeout;
    request.cachePolicy =
        NSURLRequestReloadIgnoringLocalCacheData;

    [request
        setValue:@"application/json"
        forHTTPHeaderField:@"Content-Type"];

    [request
        setValue:@"application/json"
        forHTTPHeaderField:@"Accept"];

    [request
        setValue:@"no-store"
        forHTTPHeaderField:@"Cache-Control"];

    if (authorization.length > 0) {
        [request
            setValue:
                [@"Bearer "
                    stringByAppendingString:
                        authorization]
            forHTTPHeaderField:
                @"Authorization"];
    }

    request.HTTPBody =
        bodyData;

    NSURLSessionDataTask *task =
        [self.session
            dataTaskWithRequest:request
            completionHandler:^(
                NSData *data,
                NSURLResponse *response,
                NSError *error
            ) {
        NSInteger statusCode = 0;

        if (
            [response
                isKindOfClass:
                    NSHTTPURLResponse.class]
        ) {
            statusCode =
                (
                    (NSHTTPURLResponse *)
                    response
                ).statusCode;
        }

        NSDictionary *json = nil;

        if (data.length > 0) {
            id object =
                [NSJSONSerialization
                    JSONObjectWithData:data
                    options:0
                    error:nil];

            if (
                [object
                    isKindOfClass:
                        NSDictionary.class]
            ) {
                json = object;
            }
        }

        dispatch_async(
            dispatch_get_main_queue(),
            ^{
                completion(
                    statusCode,
                    json,
                    error
                );
            }
        );
    }];

    [task resume];
}

- (void)postPath:(NSString *)path
              body:(NSDictionary *)body
        completion:(void (^)(NSInteger, NSDictionary *, NSError *))completion {
    [self
        postPath:path
        body:body
        authorization:nil
        completion:completion];
}

#pragma mark - Auth actions

- (void)detectTapped {
    NSString *hwid = [self detectHWID];
    if (hwid.length < 8) {
        [self setStatus:@"Não foi possível detectar o HWID." error:YES maintenance:NO];
        return;
    }

    self.hwidField.text = hwid;
    [self setStatus:@"HWID detectado." error:NO maintenance:NO];
}

- (void)enterTapped {
    if (self.requestInFlight) return;

    NSString *key = [self normalizedKey:self.keyField.text];
    NSString *hwid = [self.hwidField.text stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet].uppercaseString;

    if (key.length == 0) {
        [self setStatus:@"Digite sua key." error:YES maintenance:NO];
        return;
    }

    if (hwid.length < 8) {
        [self setStatus:@"Toque em Detectar para obter o HWID." error:YES maintenance:NO];
        return;
    }

    [self.keyField resignFirstResponder];
    [self authenticateKey:key hwid:hwid interactive:YES];
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    [self enterTapped];
    return YES;
}

- (NSString *)securityFailureMessage:(NSDictionary *)json
                                   fallback:(NSString *)fallback {
    NSString *message =
        [self jsonString:json key:@"message"];

    return
        message.length > 0
            ? message
            : fallback;
}

- (BOOL)handleSecurityFailureStatusCode:(NSInteger)statusCode
                                   json:(NSDictionary *)json
                            interactive:(BOOL)interactive {
    NSString *code =
        [self jsonString:json key:@"code"] ?: @"";

    if (
        [code
            isEqualToString:
                @"SERVER_MAINTENANCE"] ||
        statusCode == 503
    ) {
        NSString *message =
            [self
                securityFailureMessage:json
                fallback:
                    @"Servidor pausado devido a uma manutenção."];

        [self
            lockWithMessage:message
            maintenance:YES
            clearKey:NO];

        return YES;
    }

    BOOL success =
        [self
            jsonBool:json
            key:@"success"
            defaultValue:NO];

    if (success) {
        return NO;
    }

    NSString *fallback =
        @"Autenticação recusada pelo servidor.";

    if (
        [code
            isEqualToString:
                @"DEVICE_MISMATCH"]
    ) {
        fallback =
            @"Essa key já está vinculada a outro dispositivo.";
    } else if (
        [code
            isEqualToString:
                @"DEVICE_KEY_MISMATCH"]
    ) {
        fallback =
            @"A chave criptográfica deste dispositivo não corresponde à licença.";
    } else if (
        [code
            isEqualToString:
                @"KEY_EXPIRED"]
    ) {
        fallback =
            @"Key expirada.";
    } else if (
        [code
            isEqualToString:
                @"KEY_PAUSED"]
    ) {
        fallback =
            @"Esta key está pausada.";
    } else if (
        [code
            isEqualToString:
                @"KEY_NOT_FOUND"]
    ) {
        fallback =
            @"Key não encontrada.";
    } else if (
        [code
            isEqualToString:
                @"INVALID_HWID"]
    ) {
        fallback =
            @"HWID inválido.";
    } else if (
        [code
            isEqualToString:
                @"BUILD_BLOCKED"] ||
        [code
            isEqualToString:
                @"INTEGRITY_FAILED"]
    ) {
        fallback =
            @"Esta versão da autenticação foi bloqueada pelo servidor.";
    } else if (
        [code
            isEqualToString:
                @"RELEASE_NOT_CONFIGURED"]
    ) {
        fallback =
            @"A release da autenticação ainda não foi liberada no servidor.";
    } else if (
        [code
            isEqualToString:
                @"SIGNATURE_INVALID"] ||
        [code
            isEqualToString:
                @"REPLAY_BLOCKED"]
    ) {
        fallback =
            @"Falha na validação criptográfica.";
    }

    NSString *finalMessage =
        [self
            securityFailureMessage:json
            fallback:fallback];

    BOOL clear =
        [code
            isEqualToString:
                @"KEY_NOT_FOUND"] ||
        [code
            isEqualToString:
                @"DEVICE_MISMATCH"];

    if (
        !interactive &&
        self.unlocked
    ) {
        [self
            lockWithMessage:finalMessage
            maintenance:NO
            clearKey:clear];
    } else {
        [self
            setStatus:finalMessage
            error:YES
            maintenance:NO];
    }

    return YES;
}

- (void)authenticateKey:(NSString *)key
                   hwid:(NSString *)hwid
            interactive:(BOOL)interactive {
    if (self.requestInFlight) {
        return;
    }

    [self setBusy:YES];

    NSString *publicKey =
        [self devicePublicKeyBase64];

    NSString *dylibHash =
        EASelfDylibSHA256();

    if (
        publicKey.length == 0 ||
        dylibHash.length != 64
    ) {
        [self setBusy:NO];

        NSString *message =
            publicKey.length == 0
                ? @"Não foi possível criar a identidade criptográfica deste dispositivo."
                : @"Não foi possível validar a integridade da autenticação.";

        if (
            !interactive &&
            self.unlocked
        ) {
            [self
                lockWithMessage:message
                maintenance:NO
                clearKey:NO];
        } else {
            [self
                setStatus:message
                error:YES
                maintenance:NO];
        }
        return;
    }

    NSString *appBuild =
        [
            NSBundle.mainBundle
            objectForInfoDictionaryKey:
                @"CFBundleVersion"
        ];

    NSString *appVersion =
        [
            NSBundle.mainBundle
            objectForInfoDictionaryKey:
                @"CFBundleShortVersionString"
        ];

    NSDictionary *challengeBody = @{
        @"key":
            key ?: @"",
        @"hwid":
            hwid ?: @"",
        @"public_key":
            publicKey,
        @"build_marker":
            EABuildMarker,
        @"app_build":
            appBuild ?: @"",
        @"app_version":
            appVersion ?: @"",
        @"dylib_hash":
            dylibHash
    };

    [self
        postPath:
            @"/api/security/hwid/challenge"
        body:challengeBody
        completion:^(
            NSInteger statusCode,
            NSDictionary *json,
            NSError *error
        ) {
        if (
            error ||
            !json
        ) {
            [self setBusy:NO];

            NSString *message =
                @"Não foi possível conectar ao servidor de autenticação.";

            if (
                !interactive &&
                self.unlocked
            ) {
                [self
                    lockWithMessage:message
                    maintenance:NO
                    clearKey:NO];
            } else {
                [self
                    setStatus:message
                    error:YES
                    maintenance:NO];
            }
            return;
        }

        if (
            [self
                handleSecurityFailureStatusCode:
                    statusCode
                json:json
                interactive:interactive]
        ) {
            [self setBusy:NO];
            return;
        }

        NSString *challengeId =
            [self
                jsonString:json
                key:@"challenge_id"];

        NSString *messageToSign =
            [self
                jsonString:json
                key:@"message_to_sign"];

        if (
            challengeId.length == 0 ||
            messageToSign.length == 0
        ) {
            [self setBusy:NO];

            [self
                setStatus:
                    @"Resposta de segurança inválida."
                error:YES
                maintenance:NO];
            return;
        }

        NSString *signature =
            [self
                signatureForMessage:
                    messageToSign];

        if (signature.length == 0) {
            [self setBusy:NO];

            [self
                setStatus:
                    @"Não foi possível assinar o challenge do servidor."
                error:YES
                maintenance:NO];
            return;
        }

        NSDictionary *verifyBody = @{
            @"challenge_id":
                challengeId,
            @"signature":
                signature
        };

        [self
            postPath:
                @"/api/security/hwid/verify"
            body:verifyBody
            completion:^(
                NSInteger verifyStatusCode,
                NSDictionary *verifyJSON,
                NSError *verifyError
            ) {
            [self setBusy:NO];

            if (
                verifyError ||
                !verifyJSON
            ) {
                NSString *message =
                    @"O servidor não confirmou a sessão segura.";

                if (
                    !interactive &&
                    self.unlocked
                ) {
                    [self
                        lockWithMessage:message
                        maintenance:NO
                        clearKey:NO];
                } else {
                    [self
                        setStatus:message
                        error:YES
                        maintenance:NO];
                }
                return;
            }

            if (
                [self
                    handleSecurityFailureStatusCode:
                        verifyStatusCode
                    json:verifyJSON
                    interactive:interactive]
            ) {
                return;
            }

            NSString *status =
                [[self
                    jsonString:verifyJSON
                    key:@"status"] ?: @""
                    lowercaseString];

            NSString *sessionToken =
                [self
                    jsonString:verifyJSON
                    key:@"session_token"];

            NSString *sessionExpires =
                [self
                    jsonString:verifyJSON
                    key:@"session_expires_at"];

            NSString *heartbeatNonce =
                [self
                    jsonString:verifyJSON
                    key:@"heartbeat_nonce"];

            if (
                ![status
                    isEqualToString:
                        @"active"] ||
                sessionToken.length < 32 ||
                heartbeatNonce.length < 16
            ) {
                [self
                    setStatus:
                        @"O servidor não liberou uma sessão válida."
                    error:YES
                    maintenance:NO];
                return;
            }

            self.validatedKey =
                key;

            self.validatedHWID =
                hwid;

            self.securitySessionToken =
                sessionToken;

            self.securitySessionExpiresAt =
                sessionExpires;

            self.heartbeatNonce =
                heartbeatNonce;

            self.lastServerSuccess =
                CACurrentMediaTime();

            [self
                setKeychainString:key
                account:EAKeyAccount];

            [self
                setKeychainString:hwid
                account:EAHWIDAccount];

            [self unlock];
        }];
    }];
}

#pragma mark - Lock / unlock / revalidation

- (void)unlock {
    self.unlocked = YES;
    if (self.lastServerSuccess <= 0) {
        self.lastServerSuccess = CACurrentMediaTime();
    }
    [self setStatus:@"" error:NO maintenance:NO];

    [self.revalidateTimer invalidate];
    self.revalidateTimer = [NSTimer scheduledTimerWithTimeInterval:EARevalidateInterval
                                                            target:self
                                                          selector:@selector(periodicRevalidate)
                                                          userInfo:nil
                                                           repeats:YES];

    [self hideWindow];
}

- (void)lockWithMessage:(NSString *)message maintenance:(BOOL)maintenance clearKey:(BOOL)clearKey {
    self.unlocked = NO;
    [self.revalidateTimer invalidate];
    self.revalidateTimer = nil;

    self.securitySessionToken = nil;
    self.securitySessionExpiresAt = nil;
    self.heartbeatNonce = nil;

    if (clearKey) {
        [self setKeychainString:nil account:EAKeyAccount];
        self.validatedKey = nil;
        self.keyField.text = @"";
    } else {
        NSString *savedKey = self.validatedKey ?: [self keychainString:EAKeyAccount];
        if (savedKey.length > 0) self.keyField.text = savedKey;
    }

    NSString *savedHWID = self.validatedHWID ?: [self keychainString:EAHWIDAccount];
    if (savedHWID.length > 0) self.hwidField.text = savedHWID;

    [self showWindow];
    [self setStatus:message error:!maintenance maintenance:maintenance];
}

- (void)periodicRevalidate {
    if (
        !self.unlocked ||
        self.requestInFlight
    ) {
        return;
    }

    NSString *key =
        self.validatedKey ?:
        [self
            normalizedKey:
                [self
                    keychainString:
                        EAKeyAccount]];

    NSString *hwid =
        self.validatedHWID ?:
        [self
            keychainString:
                EAHWIDAccount];

    if (
        key.length == 0 ||
        hwid.length < 8
    ) {
        [self
            lockWithMessage:
                @"Autenticação local inválida."
            maintenance:NO
            clearKey:YES];
        return;
    }

    if (
        self.securitySessionToken.length < 32 ||
        self.heartbeatNonce.length < 16
    ) {
        [self
            authenticateKey:key
            hwid:hwid
            interactive:NO];
        return;
    }

    self.requestInFlight =
        YES;

    NSString *dylibHash =
        EASelfDylibSHA256();

    NSString *heartbeatMessage =
        [NSString stringWithFormat:
            @"EXTERNAL-HEARTBEAT-V1|%@|%@|%@|%@",
            self.securitySessionToken,
            self.heartbeatNonce,
            EABuildMarker,
            dylibHash];

    NSString *heartbeatSignature =
        [self
            signatureForMessage:
                heartbeatMessage];

    if (heartbeatSignature.length == 0) {
        self.requestInFlight = NO;

        [self
            lockWithMessage:
                @"Não foi possível assinar a validação do servidor."
            maintenance:NO
            clearKey:NO];
        return;
    }

    NSDictionary *body = @{
        @"build_marker":
            EABuildMarker,
        @"dylib_hash":
            dylibHash,
        @"signature":
            heartbeatSignature
    };

    [self
        postPath:
            @"/api/security/session/heartbeat"
        body:body
        authorization:
            self.securitySessionToken
        completion:^(
            NSInteger statusCode,
            NSDictionary *json,
            NSError *error
        ) {
        self.requestInFlight =
            NO;

        if (
            error ||
            !json
        ) {
            CFTimeInterval now =
                CACurrentMediaTime();

            if (
                self.lastServerSuccess <= 0 ||
                (
                    now -
                    self.lastServerSuccess
                ) >=
                    EAHeartbeatGraceInterval
            ) {
                [self
                    lockWithMessage:
                        @"Conexão com o servidor de autenticação perdida."
                    maintenance:NO
                    clearKey:NO];
            }

            return;
        }

        NSString *code =
            [self
                jsonString:json
                key:@"code"] ?: @"";

        if (
            [code
                isEqualToString:
                    @"SESSION_EXPIRED"] ||
            [code
                isEqualToString:
                    @"SESSION_INVALID"]
        ) {
            self.securitySessionToken =
                nil;

            self.securitySessionExpiresAt =
                nil;

            self.heartbeatNonce =
                nil;

            [self
                authenticateKey:key
                hwid:hwid
                interactive:NO];
            return;
        }

        if (
            [self
                handleSecurityFailureStatusCode:
                    statusCode
                json:json
                interactive:NO]
        ) {
            self.securitySessionToken =
                nil;
            return;
        }

        BOOL success =
            [self
                jsonBool:json
                key:@"success"
                defaultValue:NO];

        NSString *status =
            [[self
                jsonString:json
                key:@"status"] ?: @""
                lowercaseString];

        if (
            !success ||
            ![status
                isEqualToString:
                    @"active"]
        ) {
            self.securitySessionToken =
                nil;

            [self
                lockWithMessage:
                    @"A sessão foi recusada pelo servidor."
                maintenance:NO
                clearKey:NO];
            return;
        }

        NSString *nextHeartbeatNonce =
            [self
                jsonString:json
                key:@"heartbeat_nonce"];

        if (nextHeartbeatNonce.length < 16) {
            self.securitySessionToken = nil;
            self.heartbeatNonce = nil;

            [self
                lockWithMessage:
                    @"O servidor retornou um heartbeat inválido."
                maintenance:NO
                clearKey:NO];
            return;
        }

        self.heartbeatNonce =
            nextHeartbeatNonce;

        self.lastServerSuccess =
            CACurrentMediaTime();

        NSString *expires =
            [self
                jsonString:json
                key:@"session_expires_at"];

        if (expires.length > 0) {
            self.securitySessionExpiresAt =
                expires;
        }
    }];
}

#pragma mark - Lifecycle / start

- (void)didBecomeActive:(NSNotification *)note {
    self.gifDisplayLink.paused = NO;
    self.gifStartTimestamp = 0.0;

    if (self.unlocked && !self.requestInFlight) {
        [self periodicRevalidate];
    }
}

- (void)willResignActive:(NSNotification *)note {
    [self.keyField resignFirstResponder];
    self.gifDisplayLink.paused = YES;
}

- (void)start {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.started) {
            if (!self.unlocked) [self showWindow];
            return;
        }

        self.started = YES;
        self.unlocked = NO;
        NSLog(@"[ExternalAuth] %@", EABuildMarker);

        NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        configuration.timeoutIntervalForRequest = EARequestTimeout;
        configuration.timeoutIntervalForResource = EARequestTimeout + 5.0;
        configuration.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
        configuration.URLCache = nil;
        configuration.HTTPCookieStorage = nil;
        configuration.HTTPCookieAcceptPolicy = NSHTTPCookieAcceptPolicyNever;
        self.session = [NSURLSession sessionWithConfiguration:configuration delegate:self delegateQueue:nil];

        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(didBecomeActive:) name:UIApplicationDidBecomeActiveNotification object:nil];
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(willResignActive:) name:UIApplicationWillResignActiveNotification object:nil];

        [self buildUI];
        [self showWindow];

        NSString *savedKey = [self normalizedKey:[self keychainString:EAKeyAccount]];
        NSString *savedHWID = [self keychainString:EAHWIDAccount];

        if (savedKey.length > 0) self.keyField.text = savedKey;
        if (savedHWID.length > 0) self.hwidField.text = savedHWID;

        // Se ja existe key + HWID salvos, valida automaticamente.
        // Isso tambem faz o modo manutencao recolocar a tela de login.
        if (savedKey.length > 0 && savedHWID.length >= 8) {
            self.validatedKey = savedKey;
            self.validatedHWID = savedHWID;
            [self authenticateKey:savedKey hwid:savedHWID interactive:YES];
        }
    });
}

#pragma mark - TLS

- (void)URLSession:(NSURLSession *)session
        didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
          completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential * _Nullable credential))completionHandler {
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

@end

__attribute__((constructor))
static void ExternalAuthInit(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        dispatch_after(
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.08 * NSEC_PER_SEC)),
            dispatch_get_main_queue(),
            ^{
                [[ExternalAuthManager shared] start];
            }
        );
    });
}

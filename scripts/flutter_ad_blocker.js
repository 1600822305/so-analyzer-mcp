/**
 * Flutter 通用去广告 Frida Hook 脚本
 * 适用于: AdMob, 自定义广告, WebView广告等
 * 
 * 使用方法:
 * frida -U -f <package_name> -l flutter_ad_blocker.js --no-pause
 */

'use strict';

console.log("[*] Flutter Ad Blocker Script Loaded");

// ==================== 配置 ====================

const CONFIG = {
    // 是否打印调试信息
    debug: true,
    // 是否拦截广告请求
    blockAdRequests: true,
    // 是否隐藏广告View
    hideAdViews: true,
    // VIP相关Hook
    hookVip: true
};

function log(msg) {
    if (CONFIG.debug) console.log("[AD-BLOCKER] " + msg);
}

// ==================== 等待模块加载 ====================

var libapp = null;
var libflutter = null;

function waitForModule(name, callback) {
    var module = Process.findModuleByName(name);
    if (module) {
        callback(module);
    } else {
        setTimeout(function() {
            waitForModule(name, callback);
        }, 100);
    }
}

// ==================== 方案1: Hook Android广告SDK ====================

function hookAndroidAds() {
    log("Hooking Android Ad SDKs...");
    
    // Hook Google AdMob
    try {
        var AdView = Java.use("com.google.android.gms.ads.AdView");
        AdView.loadAd.implementation = function(adRequest) {
            log("Blocked AdView.loadAd()");
            return;
        };
    } catch(e) {}
    
    try {
        var InterstitialAd = Java.use("com.google.android.gms.ads.InterstitialAd");
        InterstitialAd.loadAd.implementation = function(adRequest) {
            log("Blocked InterstitialAd.loadAd()");
            return;
        };
        InterstitialAd.show.implementation = function() {
            log("Blocked InterstitialAd.show()");
            return;
        };
    } catch(e) {}
    
    try {
        var RewardedAd = Java.use("com.google.android.gms.ads.rewarded.RewardedAd");
        RewardedAd.load.implementation = function(context, adUnitId, adRequest, callback) {
            log("Blocked RewardedAd.load()");
            return;
        };
    } catch(e) {}
    
    // Hook AdMob初始化
    try {
        var MobileAds = Java.use("com.google.android.gms.ads.MobileAds");
        MobileAds.initialize.overload('android.content.Context').implementation = function(ctx) {
            log("Blocked MobileAds.initialize()");
            return;
        };
        MobileAds.initialize.overload('android.content.Context', 'com.google.android.gms.ads.initialization.OnInitializationCompleteListener').implementation = function(ctx, listener) {
            log("Blocked MobileAds.initialize() with callback");
            return;
        };
    } catch(e) {}
    
    // Hook Unity Ads
    try {
        var UnityAds = Java.use("com.unity3d.ads.UnityAds");
        UnityAds.show.implementation = function(activity, placementId, options, listener) {
            log("Blocked UnityAds.show()");
            return;
        };
    } catch(e) {}
    
    // Hook Facebook Ads
    try {
        var AdViewFB = Java.use("com.facebook.ads.AdView");
        AdViewFB.loadAd.implementation = function() {
            log("Blocked Facebook AdView.loadAd()");
            return;
        };
    } catch(e) {}
    
    log("Android Ad SDK hooks installed");
}

// ==================== 方案2: Hook Flutter MethodChannel ====================

function hookFlutterMethodChannel() {
    log("Hooking Flutter MethodChannel for ads...");
    
    try {
        var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
        var originalInvokeMethod = MethodChannel.invokeMethod.overload('java.lang.String', 'java.lang.Object');
        
        originalInvokeMethod.implementation = function(method, args) {
            var methodStr = method ? method.toString() : "";
            
            // 拦截广告相关方法
            if (methodStr.includes("loadAd") || 
                methodStr.includes("showAd") ||
                methodStr.includes("loadInterstitial") ||
                methodStr.includes("showInterstitial") ||
                methodStr.includes("loadReward") ||
                methodStr.includes("showReward") ||
                methodStr.includes("loadBanner")) {
                log("Blocked MethodChannel: " + methodStr);
                return;
            }
            
            return originalInvokeMethod.call(this, method, args);
        };
    } catch(e) {
        log("MethodChannel hook failed: " + e);
    }
}

// ==================== 方案3: Hook libapp.so中的广告函数 ====================

function hookLibappAds(libapp) {
    log("Hooking libapp.so ad functions...");
    
    // 常见广告函数地址模式（需要根据具体APP调整）
    var adFunctions = [
        // 格式: {name: "函数名", offset: 0x地址}
        // 这些需要通过Blutter分析获取
    ];
    
    // 通用Hook - 搜索广告相关字符串
    var adPatterns = [
        "showAd",
        "loadAd",
        "displayAd",
        "interstitial",
        "rewarded",
        "banner",
        "admob",
        "adUnit"
    ];
    
    // 如果有具体地址，直接Hook
    adFunctions.forEach(function(func) {
        try {
            Interceptor.attach(libapp.base.add(func.offset), {
                onEnter: function(args) {
                    log("Blocked: " + func.name);
                },
                onLeave: function(retval) {
                    retval.replace(0);  // 返回失败
                }
            });
        } catch(e) {}
    });
}

// ==================== 方案4: 网络层拦截广告请求 ====================

function hookNetworkAds() {
    log("Hooking network layer for ad requests...");
    
    // 广告域名列表
    var adDomains = [
        "googleads",
        "googlesyndication",
        "doubleclick",
        "admob",
        "adservice",
        "adsserver",
        "adnxs",
        "facebook.com/tr",
        "unity3d.com/ads",
        "applovin",
        "chartboost",
        "ironsource",
        "mopub",
        "inmobi",
        "vungle"
    ];
    
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function() {
            var url = this.toString();
            
            for (var i = 0; i < adDomains.length; i++) {
                if (url.toLowerCase().includes(adDomains[i])) {
                    log("Blocked ad request: " + url);
                    throw new Error("Ad blocked");
                }
            }
            
            return this.openConnection();
        };
    } catch(e) {}
    
    // Hook OkHttp
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Builder = Java.use("okhttp3.OkHttpClient$Builder");
        
        var Interceptor = Java.use("okhttp3.Interceptor");
        var InterceptorImpl = Java.registerClass({
            name: "com.adblocker.AdInterceptor",
            implements: [Interceptor],
            methods: {
                intercept: function(chain) {
                    var request = chain.request();
                    var url = request.url().toString();
                    
                    for (var i = 0; i < adDomains.length; i++) {
                        if (url.toLowerCase().includes(adDomains[i])) {
                            log("OkHttp blocked: " + url);
                            // 返回空响应
                            var Response = Java.use("okhttp3.Response");
                            var ResponseBody = Java.use("okhttp3.ResponseBody");
                            return Response.$new.Builder()
                                .request(request)
                                .protocol(Java.use("okhttp3.Protocol").HTTP_1_1.value)
                                .code(204)
                                .message("No Content - Ad Blocked")
                                .body(ResponseBody.create(null, ""))
                                .build();
                        }
                    }
                    
                    return chain.proceed(request);
                }
            }
        });
    } catch(e) {}
}

// ==================== 方案5: Hook VIP状态 ====================

function hookVipStatus() {
    log("Hooking VIP status...");
    
    // 常见VIP字段名
    var vipFields = [
        "isVip",
        "isPremium", 
        "isMember",
        "isSubscribed",
        "isPaid",
        "isAdFree",
        "hasSubscription",
        "expiredVip",
        "vipLevel"
    ];
    
    // 这需要配合Blutter分析结果使用
    // 示例: Hook UserInfo类的VIP字段getter
}

// ==================== 方案6: View层隐藏广告 ====================

function hideAdViews() {
    log("Setting up ad view hiding...");
    
    try {
        var View = Java.use("android.view.View");
        var GONE = 8;
        
        // Hook setVisibility
        var originalSetVisibility = View.setVisibility;
        View.setVisibility.implementation = function(visibility) {
            // 检查是否是广告View
            var className = this.getClass().getName();
            if (className.includes("AdView") || 
                className.includes("BannerAd") ||
                className.includes("NativeAd")) {
                log("Hiding ad view: " + className);
                return originalSetVisibility.call(this, GONE);
            }
            return originalSetVisibility.call(this, visibility);
        };
    } catch(e) {}
}

// ==================== 特定APP Hook (mitao_app示例) ====================

function hookMitaoApp(libapp) {
    log("Hooking mitao_app specific functions...");
    
    // 基于Blutter分析结果的地址
    var mitaoHooks = [
        // 广告跳转
        {name: "kAdjump", offset: 0x5d74b4, action: "block"},
        {name: "jumpExternalAddress", offset: 0x5d7640, action: "block"},
        {name: "clickAdReport", offset: 0x5d7c6c, action: "block"},
    ];
    
    mitaoHooks.forEach(function(hook) {
        try {
            Interceptor.attach(libapp.base.add(hook.offset), {
                onEnter: function(args) {
                    log("Intercepted: " + hook.name);
                    if (hook.action === "block") {
                        // 跳过函数执行
                        this.blocked = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.blocked) {
                        retval.replace(0);
                    }
                }
            });
            log("Hooked: " + hook.name + " @ 0x" + hook.offset.toString(16));
        } catch(e) {
            log("Failed to hook " + hook.name + ": " + e);
        }
    });
}

// ==================== 主入口 ====================

Java.perform(function() {
    log("Starting Flutter Ad Blocker...");
    
    // 1. Hook Android广告SDK
    if (CONFIG.blockAdRequests) {
        hookAndroidAds();
    }
    
    // 2. Hook Flutter MethodChannel
    hookFlutterMethodChannel();
    
    // 3. Hook网络层
    if (CONFIG.blockAdRequests) {
        hookNetworkAds();
    }
    
    // 4. 隐藏广告View
    if (CONFIG.hideAdViews) {
        hideAdViews();
    }
    
    // 5. Hook VIP状态
    if (CONFIG.hookVip) {
        hookVipStatus();
    }
    
    log("Android layer hooks installed");
});

// 6. Hook libapp.so
waitForModule('libapp.so', function(module) {
    libapp = module;
    log("libapp.so loaded at: " + libapp.base);
    
    // Hook libapp中的广告函数
    hookLibappAds(libapp);
    
    // 特定APP Hook
    // hookMitaoApp(libapp);  // 取消注释启用
    
    log("Native layer hooks installed");
});

console.log("[*] Flutter Ad Blocker Ready!");
console.log("[*] Waiting for libapp.so to load...");

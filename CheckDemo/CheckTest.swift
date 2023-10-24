//
//  CheckTest.swift
//  TestProj
//
//  Created by ijm-ycy on 20.12.21.
//

import Foundation
import MachO
import UIKit

/*
 ⚠️⚠️⚠️查找风险对应符号在哪个地方
 先在工程中搜索符号，工程中没有，有可能是第三方库包含了，可以使用nm命令查找在哪个第三方库

 nm -pa <macho文件路径> | grep '符号'
 例如:
 nm -pa AFNetorking.framework/AFNetorking | grep 'UIWebView'
 nm -pa CheckDemo.app/CheckDemo | grep 'UIWebView'
 nm -pa libStatic.a | grep 'UIWebView'
 **/
@objc
public class CheckTest : NSObject {
    static var _whitelistFramework: Array<String>?
    
    @objc
    static public func test_obf() {
        
        if #available(iOS 15.0, *) {
            UITableView.appearance().sectionHeaderTopPadding = 0
        } else {
            // Fallback on earlier versions
        }
    }
    
    @objc
    static public func testAll() {
        
        // 越狱设备运行风险
        print(">>>>>checkIsJailbroken = %d", isJbroken());
        
        // 动态调试攻击风险
        let isDebug = amIDebugged()
        print("检测是否有调试应用 = %d", isDebug);
        
        // 检测是否使用代理
        print(">>>>>iproxy:%d", isSettingProxy());
        
        // 注入攻击风险
        if IJMCheckInsertWhiteList() || IJMCheckInsertLib() {
            print("检测到动态库注入");
        } else {
            print("没有检测到动态库注入");
        }
        
        let isOrigin = checkCodesign(teamID: "K294UE6ZZL");
        print("是否未篡改, isOrigin = %d", isOrigin);
    }
    
    /// MARK: - 判断是否使用了越狱设备运行
    @inline(__always)
    static func isJbroken() -> Bool {
        var jailbroken = false;
        let breakDir = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib"
            ]
        
        for dir in breakDir {
            if FileManager.default.fileExists(atPath: dir){
                jailbroken = true;
            }
        }
        
        var stat_info = stat()
        if 0 == stat("/Applications/Cydia.app", &stat_info) {
            jailbroken = true;
        }
        
        var lstat_info = stat()
        if 0 == lstat("/Applications/Cydia.app", &lstat_info) {
            jailbroken = true;
        }
        
        // 防止越狱状态下，动态库注入
        if getenv("DYLD_INSERT_LIBRARIES") != nil {
            jailbroken = true;
        }
        
        return jailbroken;
    }
    
    /// 动态调试攻击风险
    /// - Returns: 是否有动态调试
    @objc
    static func amIDebugged() -> Bool {
        var kinfo = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let sysctlRet = sysctl(&mib, UInt32(mib.count), &kinfo, &size, nil, 0)

        if sysctlRet != 0 {
            print("Error occured when calling sysctl(). The debugger check may not be reliable")
        }
        return (kinfo.kp_proc.p_flag & P_TRACED) != 0
    }
    
    /// 判断是否使用网络代理
    /// - Returns: 是否使用网络代理
    @inline(__always)
    static func isSettingProxy() -> Bool {
        guard let proxy = CFNetworkCopySystemProxySettings()?.takeUnretainedValue() else { return false }
        guard let dict = proxy as? [String: Any] else { return false }
        guard let HTTPProxy = dict["HTTPProxy"] as? String else { return false }

        if (HTTPProxy.count > 0) {
            return true
        }
        
        return false
    }
    
    /// 注入攻击风险防护
    /// - Returns: 是否有插入动态库
    @inline(__always)
    static func IJMCheckInsertLib() -> Bool {
        guard let _ = getenv("DYLD_INSERT_LIBRARIES") else { return false }
        return true; //不为NULL表示有动态库注入
    }
    
    /// 注入攻击风险防护
    /// - Returns: 是否有注入动态库
    @inline(__always)
    static func IJMCheckInsertWhiteList() -> Bool {
        _whitelistFramework = []
        _whitelistFramework?.append("/TestFramework.framework/TestFramework")
        
        let count = _dyld_image_count();
        for i in 0..<count {
            let filePath = String(validatingUTF8: _dyld_get_image_name(i)!)!
            let arrs = filePath.components(separatedBy: ".app/Frameworks")
            if arrs.count > 1 {
                print(arrs[1])
                if !_whitelistFramework!.contains(arrs[1]) {
                    return true
                }
            }
        }
        return false
    }
    
    /// 篡改和二次打包风险
    /// - Parameter teamID: 参数为打包证书的teamID, 可先用发布证书打包出来后，然后查看打印日志得到，也可使用ldid -e <macho文件>得到
    /// - Returns: 是否未篡改
    @inline(__always)
    static func checkCodesign(teamID: String) -> Bool {
        let embeddedPath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision")!
        
        if FileManager.default.fileExists(atPath: embeddedPath) {
            // 读取 application-identifier
            let embeddedProvisioning = try? String.init(contentsOfFile: embeddedPath, encoding: String.Encoding.ascii)
            let embeddedProvisioningLines = embeddedProvisioning?.components(separatedBy: .newlines)
            
            for i in 0 ..< embeddedProvisioningLines!.count {
                let emStr = embeddedProvisioningLines![i] as NSString
                
                if (emStr.range(of: "application-identifier").location != NSNotFound) && ((i+1) < embeddedProvisioningLines!.count) {
                    
                    let positionStr = embeddedProvisioningLines![i + 1] as NSString
                    
                    let rangePrefix = positionStr.range(of: "<string>")
                    let rangeSuffix = positionStr.range(of: "</string>")
                    
                    if rangePrefix.location != NSNotFound && rangeSuffix.location != NSNotFound {
                        let range: NSRange = NSRange.init(location: rangePrefix.location + rangePrefix.length, length: rangeSuffix.location - (rangePrefix.location + rangePrefix.length))
                        
                        let fullIdentifier = positionStr.substring(with: range)
                        let identifierComponents = fullIdentifier.components(separatedBy: ".") as Array
                        let appIdentifier = identifierComponents.first
                        
                        if appIdentifier != teamID {
                            return false
                        } else {
                            return true
                        }
                    }
                }
            }
        }
        
        return true
    }
}

"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[7895],{3905:(e,t,n)=>{n.d(t,{Zo:()=>l,kt:()=>y});var r=n(67294);function i(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function a(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function o(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?a(Object(n),!0).forEach((function(t){i(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):a(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function s(e,t){if(null==e)return{};var n,r,i=function(e,t){if(null==e)return{};var n,r,i={},a=Object.keys(e);for(r=0;r<a.length;r++)n=a[r],t.indexOf(n)>=0||(i[n]=e[n]);return i}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(r=0;r<a.length;r++)n=a[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(i[n]=e[n])}return i}var p=r.createContext({}),c=function(e){var t=r.useContext(p),n=t;return e&&(n="function"==typeof e?e(t):o(o({},t),e)),n},l=function(e){var t=c(e.components);return r.createElement(p.Provider,{value:t},e.children)},m="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},d=r.forwardRef((function(e,t){var n=e.components,i=e.mdxType,a=e.originalType,p=e.parentName,l=s(e,["components","mdxType","originalType","parentName"]),m=c(n),d=i,y=m["".concat(p,".").concat(d)]||m[d]||u[d]||a;return n?r.createElement(y,o(o({ref:t},l),{},{components:n})):r.createElement(y,o({ref:t},l))}));function y(e,t){var n=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var a=n.length,o=new Array(a);o[0]=d;var s={};for(var p in t)hasOwnProperty.call(t,p)&&(s[p]=t[p]);s.originalType=e,s[m]="string"==typeof e?e:i,o[1]=s;for(var c=2;c<a;c++)o[c]=n[c];return r.createElement.apply(null,o)}return r.createElement.apply(null,n)}d.displayName="MDXCreateElement"},80762:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>p,contentTitle:()=>o,default:()=>u,frontMatter:()=>a,metadata:()=>s,toc:()=>c});var r=n(87462),i=(n(67294),n(3905));const a={hide_table_of_contents:!0,description:"Querying the IPSWs for files containing a specific entitlement"},o="Parse Entitlements",s={unversionedId:"guides/ent",id:"guides/ent",title:"Parse Entitlements",description:"Querying the IPSWs for files containing a specific entitlement",source:"@site/docs/guides/ent.md",sourceDirName:"guides",slug:"/guides/ent",permalink:"/ipsw/docs/guides/ent",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/guides/ent.md",tags:[],version:"current",frontMatter:{hide_table_of_contents:!0,description:"Querying the IPSWs for files containing a specific entitlement"},sidebar:"docs",previous:{title:"Lookup DSC Symbols",permalink:"/ipsw/docs/guides/dump_dsc_syms"},next:{title:"Parse Img4",permalink:"/ipsw/docs/guides/img4"}},p={},c=[{value:"Search IPSW filesystem DMG for MachOs with a given <strong>entitlement</strong> <code>&lt;true/&gt;</code>",id:"search-ipsw-filesystem-dmg-for-machos-with-a-given-entitlement-true",level:3},{value:"Search IPSW filesystem DMG for MachOs with a given <strong>file name</strong> and dump it&#39;s entitlements",id:"search-ipsw-filesystem-dmg-for-machos-with-a-given-file-name-and-dump-its-entitlements",level:3},{value:"Diff two IPSWs",id:"diff-two-ipsws",level:3}],l={toc:c},m="wrapper";function u(e){let{components:t,...n}=e;return(0,i.kt)(m,(0,r.Z)({},l,n,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h1",{id:"parse-entitlements"},"Parse Entitlements"),(0,i.kt)("h3",{id:"search-ipsw-filesystem-dmg-for-machos-with-a-given-entitlement-true"},"Search IPSW filesystem DMG for MachOs with a given ",(0,i.kt)("strong",{parentName:"h3"},"entitlement")," ",(0,i.kt)("inlineCode",{parentName:"h3"},"<true/>")),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"\u276f ipsw ent iPhone11,8,iPhone12,1_14.5_18E5199a_Restore.ipsw --ent platform-application\n   \u2022 Found ipsw entitlement database file...\n   \u2022 Files containing entitlement: platform-application\n\nplatform-application /System/Library/PrivateFrameworks/MobileAccessoryUpdater.framework/XPCServices/EAUpdaterService.xpc/EAUpdaterService\nplatform-application /private/var/staged_system_apps/Home.app/Home\nplatform-application /usr/libexec/morphunassetsupdaterd\nplatform-application /System/Library/Frameworks/CryptoTokenKit.framework/PlugIns/setoken.appex/setoken\nplatform-application /usr/libexec/swcd\n<SNIP>\n")),(0,i.kt)("h3",{id:"search-ipsw-filesystem-dmg-for-machos-with-a-given-file-name-and-dump-its-entitlements"},"Search IPSW filesystem DMG for MachOs with a given ",(0,i.kt)("strong",{parentName:"h3"},"file name")," and dump it's entitlements"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},'\u276f ipsw ent iPhone11,8,iPhone12,1_14.5_18E5199a_Restore.ipsw --file WebContent\n   \u2022 Found ipsw entitlement database file...\n   \u2022 /Applications/WebContentAnalysisUI.app/WebContentAnalysisUI\n\n<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n    <key>com.apple.UIKit.vends-view-services</key>\n    <true/>\n    <key>com.apple.private.screen-time</key>\n    <true/>\n    <key>com.apple.private.security.container-required</key>\n    <true/>\n    <key>com.apple.security.exception.shared-preference.read-only</key>\n    <array>\n        <string>com.apple.springboard</string>\n    </array>\n    <key>keychain-access-groups</key>\n    <array>\n        <string>apple</string>\n        <string>com.apple.preferences</string>\n    </array>\n</dict>\n</plist>\n\n   \u2022 /System/Library/Frameworks/WebKit.framework/XPCServices/com.apple.WebKit.WebContent.xpc/com.apple.WebKit.WebContent\n\n<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n    <key>com.apple.QuartzCore.secure-mode</key>\n    <true/>\n    <key>com.apple.QuartzCore.webkit-end-points</key>\n    <true/>\n    <key>com.apple.mediaremote.set-playback-state</key>\n    <true/>\n    <key>com.apple.pac.shared_region_id</key>\n    <string>WebContent</string>\n    <key>com.apple.private.allow-explicit-graphics-priority</key>\n    <true/>\n    <key>com.apple.private.coremedia.extensions.audiorecording.allow</key>\n    <true/>\n    <key>com.apple.private.coremedia.pidinheritance.allow</key>\n    <true/>\n    <key>com.apple.private.memorystatus</key>\n    <true/>\n    <key>com.apple.private.network.socket-delegate</key>\n    <true/>\n    <key>com.apple.private.pac.exception</key>\n    <true/>\n    <key>com.apple.private.security.message-filter</key>\n    <true/>\n    <key>com.apple.private.webinspector.allow-remote-inspection</key>\n    <true/>\n    <key>com.apple.private.webinspector.proxy-application</key>\n    <true/>\n    <key>com.apple.private.webkit.use-xpc-endpoint</key>\n    <true/>\n    <key>com.apple.runningboard.assertions.webkit</key>\n    <true/>\n    <key>com.apple.tcc.delegated-services</key>\n    <array>\n        <string>kTCCServiceCamera</string>\n        <string>kTCCServiceMicrophone</string>\n    </array>\n    <key>dynamic-codesigning</key>\n    <true/>\n    <key>seatbelt-profiles</key>\n    <array>\n        <string>com.apple.WebKit.WebContent</string>\n    </array>\n</dict>\n</plist>\n')),(0,i.kt)("p",null,"Use a previously created entitlements database"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"\u276f ipsw ent iPhone11,8,iPhone12,1_14.5_18E5199a_Restore.ipsw --ent platform-application --db /tmp/IPSW.entDB\n")),(0,i.kt)("admonition",{title:"note",type:"info"},(0,i.kt)("p",{parentName:"admonition"},"When you run the ",(0,i.kt)("inlineCode",{parentName:"p"},"ipsw ent")," command on an ",(0,i.kt)("strong",{parentName:"p"},"IPSW")," it will auto-create ",(0,i.kt)("strong",{parentName:"p"},"IPSW.entDB")," next to the ",(0,i.kt)("strong",{parentName:"p"},"IPSW")," file and it will try and use that if you run it again on the same ",(0,i.kt)("strong",{parentName:"p"},"IPSW"),".")),(0,i.kt)("h3",{id:"diff-two-ipsws"},"Diff two IPSWs"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-bash"},"\u276f ipsw ent --diff test-caches/IPSWs/iPhone15,2_16.1_20B5050f_Restore.ipsw test-caches/IPSWs/iPhone15,2_16.1_20B5056e_Restore.ipsw\n")))}u.isMDXComponent=!0}}]);
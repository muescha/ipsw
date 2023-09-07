"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[7977],{3905:(e,t,r)=>{r.d(t,{Zo:()=>c,kt:()=>u});var n=r(67294);function i(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function o(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function p(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?o(Object(r),!0).forEach((function(t){i(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):o(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function a(e,t){if(null==e)return{};var r,n,i=function(e,t){if(null==e)return{};var r,n,i={},o=Object.keys(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||(i[r]=e[r]);return i}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(i[r]=e[r])}return i}var l=n.createContext({}),s=function(e){var t=n.useContext(l),r=t;return e&&(r="function"==typeof e?e(t):p(p({},t),e)),r},c=function(e){var t=s(e.components);return n.createElement(l.Provider,{value:t},e.children)},d="mdxType",f={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},m=n.forwardRef((function(e,t){var r=e.components,i=e.mdxType,o=e.originalType,l=e.parentName,c=a(e,["components","mdxType","originalType","parentName"]),d=s(r),m=i,u=d["".concat(l,".").concat(m)]||d[m]||f[m]||o;return r?n.createElement(u,p(p({ref:t},c),{},{components:r})):n.createElement(u,p({ref:t},c))}));function u(e,t){var r=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var o=r.length,p=new Array(o);p[0]=m;var a={};for(var l in t)hasOwnProperty.call(t,l)&&(a[l]=t[l]);a.originalType=e,a[d]="string"==typeof e?e:i,p[1]=a;for(var s=2;s<o;s++)p[s]=r[s];return n.createElement.apply(null,p)}return n.createElement.apply(null,r)}m.displayName="MDXCreateElement"},19257:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>l,contentTitle:()=>p,default:()=>f,frontMatter:()=>o,metadata:()=>a,toc:()=>s});var n=r(87462),i=(r(67294),r(3905));const o={id:"rm",title:"rm",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"rm",description:"Delete a provisioning profile that is used for app development or distribution"},p=void 0,a={unversionedId:"cli/ipsw/appstore/profile/rm",id:"cli/ipsw/appstore/profile/rm",title:"rm",description:"Delete a provisioning profile that is used for app development or distribution",source:"@site/docs/cli/ipsw/appstore/profile/rm.md",sourceDirName:"cli/ipsw/appstore/profile",slug:"/cli/ipsw/appstore/profile/rm",permalink:"/ipsw/docs/cli/ipsw/appstore/profile/rm",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/appstore/profile/rm.md",tags:[],version:"current",frontMatter:{id:"rm",title:"rm",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"rm",description:"Delete a provisioning profile that is used for app development or distribution"},sidebar:"cli",previous:{title:"renew",permalink:"/ipsw/docs/cli/ipsw/appstore/profile/renew"},next:{title:"token",permalink:"/ipsw/docs/cli/ipsw/appstore/token"}},l={},s=[{value:"ipsw appstore profile rm",id:"ipsw-appstore-profile-rm",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],c={toc:s},d="wrapper";function f(e){let{components:t,...r}=e;return(0,i.kt)(d,(0,n.Z)({},c,r,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h2",{id:"ipsw-appstore-profile-rm"},"ipsw appstore profile rm"),(0,i.kt)("p",null,"Delete a provisioning profile that is used for app development or distribution"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"ipsw appstore profile rm [flags]\n")),(0,i.kt)("h3",{id:"options"},"Options"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"  -h, --help          help for rm\n      --id string     Profile ID to renew\n  -n, --name string   Profile name to renew\n")),(0,i.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"      --color           colorize output\n      --config string   config file (default is $HOME/.config/ipsw/config.yaml)\n  -i, --iss string      Issuer ID\n  -j, --jwt string      JWT api key\n  -k, --kid string      Key ID\n  -p, --p8 string       Path to App Store Connect API Key (.p8)\n  -V, --verbose         verbose output\n")),(0,i.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/appstore/profile"},"ipsw appstore profile"),"\t - Create, delete, and download provisioning profiles that enable app installations for development and distribution")))}f.isMDXComponent=!0}}]);
"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[9686],{3905:(e,t,r)=>{r.d(t,{Zo:()=>l,kt:()=>f});var n=r(67294);function i(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function o(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function p(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?o(Object(r),!0).forEach((function(t){i(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):o(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function s(e,t){if(null==e)return{};var r,n,i=function(e,t){if(null==e)return{};var r,n,i={},o=Object.keys(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||(i[r]=e[r]);return i}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(i[r]=e[r])}return i}var a=n.createContext({}),c=function(e){var t=n.useContext(a),r=t;return e&&(r="function"==typeof e?e(t):p(p({},t),e)),r},l=function(e){var t=c(e.components);return n.createElement(a.Provider,{value:t},e.children)},m="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},u=n.forwardRef((function(e,t){var r=e.components,i=e.mdxType,o=e.originalType,a=e.parentName,l=s(e,["components","mdxType","originalType","parentName"]),m=c(r),u=i,f=m["".concat(a,".").concat(u)]||m[u]||d[u]||o;return r?n.createElement(f,p(p({ref:t},l),{},{components:r})):n.createElement(f,p({ref:t},l))}));function f(e,t){var r=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var o=r.length,p=new Array(o);p[0]=u;var s={};for(var a in t)hasOwnProperty.call(t,a)&&(s[a]=t[a]);s.originalType=e,s[m]="string"==typeof e?e:i,p[1]=s;for(var c=2;c<o;c++)p[c]=r[c];return n.createElement.apply(null,p)}return n.createElement.apply(null,r)}u.displayName="MDXCreateElement"},58173:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>a,contentTitle:()=>p,default:()=>d,frontMatter:()=>o,metadata:()=>s,toc:()=>c});var n=r(87462),i=(r(67294),r(3905));const o={id:"rm",title:"rm",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"rm",description:"Revoke a lost, stolen, compromised, or expiring signing certificate"},p=void 0,s={unversionedId:"cli/ipsw/appstore/cert/rm",id:"cli/ipsw/appstore/cert/rm",title:"rm",description:"Revoke a lost, stolen, compromised, or expiring signing certificate",source:"@site/docs/cli/ipsw/appstore/cert/rm.md",sourceDirName:"cli/ipsw/appstore/cert",slug:"/cli/ipsw/appstore/cert/rm",permalink:"/ipsw/docs/cli/ipsw/appstore/cert/rm",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/appstore/cert/rm.md",tags:[],version:"current",frontMatter:{id:"rm",title:"rm",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"rm",description:"Revoke a lost, stolen, compromised, or expiring signing certificate"},sidebar:"cli",previous:{title:"ls",permalink:"/ipsw/docs/cli/ipsw/appstore/cert/ls"},next:{title:"device",permalink:"/ipsw/docs/cli/ipsw/appstore/device/"}},a={},c=[{value:"ipsw appstore cert rm",id:"ipsw-appstore-cert-rm",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],l={toc:c},m="wrapper";function d(e){let{components:t,...r}=e;return(0,i.kt)(m,(0,n.Z)({},l,r,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h2",{id:"ipsw-appstore-cert-rm"},"ipsw appstore cert rm"),(0,i.kt)("p",null,"Revoke a lost, stolen, compromised, or expiring signing certificate"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"ipsw appstore cert rm [flags]\n")),(0,i.kt)("h3",{id:"options"},"Options"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"  -h, --help        help for rm\n      --id string   Profile ID to renew\n")),(0,i.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"      --color           colorize output\n      --config string   config file (default is $HOME/.config/ipsw/config.yaml)\n  -i, --iss string      Issuer ID\n  -j, --jwt string      JWT api key\n  -k, --kid string      Key ID\n  -p, --p8 string       Path to App Store Connect API Key (.p8)\n  -V, --verbose         verbose output\n")),(0,i.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/appstore/cert"},"ipsw appstore cert"),"\t - Create, download, and revoke signing certificates for app development and distribution")))}d.isMDXComponent=!0}}]);
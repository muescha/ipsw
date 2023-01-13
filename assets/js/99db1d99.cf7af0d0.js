"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[9578],{3905:(e,t,r)=>{r.d(t,{Zo:()=>p,kt:()=>m});var n=r(7294);function a(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function c(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function o(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?c(Object(r),!0).forEach((function(t){a(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):c(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function i(e,t){if(null==e)return{};var r,n,a=function(e,t){if(null==e)return{};var r,n,a={},c=Object.keys(e);for(n=0;n<c.length;n++)r=c[n],t.indexOf(r)>=0||(a[r]=e[r]);return a}(e,t);if(Object.getOwnPropertySymbols){var c=Object.getOwnPropertySymbols(e);for(n=0;n<c.length;n++)r=c[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(a[r]=e[r])}return a}var l=n.createContext({}),s=function(e){var t=n.useContext(l),r=t;return e&&(r="function"==typeof e?e(t):o(o({},t),e)),r},p=function(e){var t=s(e.components);return n.createElement(l.Provider,{value:t},e.children)},d="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},f=n.forwardRef((function(e,t){var r=e.components,a=e.mdxType,c=e.originalType,l=e.parentName,p=i(e,["components","mdxType","originalType","parentName"]),d=s(r),f=a,m=d["".concat(l,".").concat(f)]||d[f]||u[f]||c;return r?n.createElement(m,o(o({ref:t},p),{},{components:r})):n.createElement(m,o({ref:t},p))}));function m(e,t){var r=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var c=r.length,o=new Array(c);o[0]=f;var i={};for(var l in t)hasOwnProperty.call(t,l)&&(i[l]=t[l]);i.originalType=e,i[d]="string"==typeof e?e:a,o[1]=i;for(var s=2;s<c;s++)o[s]=r[s];return n.createElement.apply(null,o)}return n.createElement.apply(null,r)}f.displayName="MDXCreateElement"},3959:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>l,contentTitle:()=>o,default:()=>d,frontMatter:()=>c,metadata:()=>i,toc:()=>s});var n=r(7462),a=(r(7294),r(3905));const c={id:"extract",title:"extract",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"extract",description:"Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW/OTA",last_update:{date:new Date("2023-01-13T18:46:22.000Z"),author:"blacktop"}},o=void 0,i={unversionedId:"cli/ipsw/extract",id:"cli/ipsw/extract",title:"extract",description:"Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW/OTA",source:"@site/docs/cli/ipsw/extract.md",sourceDirName:"cli/ipsw",slug:"/cli/ipsw/extract",permalink:"/ipsw/docs/cli/ipsw/extract",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/extract.md",tags:[],version:"current",frontMatter:{id:"extract",title:"extract",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"extract",description:"Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW/OTA",last_update:{date:"2023-01-13T18:46:22.000Z",author:"blacktop"}},sidebar:"cli",previous:{title:"ent",permalink:"/ipsw/docs/cli/ipsw/ent"},next:{title:"iboot",permalink:"/ipsw/docs/cli/ipsw/iboot"}},l={},s=[{value:"ipsw extract",id:"ipsw-extract",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],p={toc:s};function d(e){let{components:t,...r}=e;return(0,a.kt)("wrapper",(0,n.Z)({},p,r,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("h2",{id:"ipsw-extract"},"ipsw extract"),(0,a.kt)("p",null,"Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW/OTA"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre"},"ipsw extract <IPSW/OTA | URL> [flags]\n")),(0,a.kt)("h3",{id:"options"},"Options"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre"},"  -m, --dmg                     Extract File System DMG file\n  -t, --dtree                   Extract DeviceTree\n  -d, --dyld                    Extract dyld_shared_cache\n  -a, --dyld-arch stringArray   dyld_shared_cache architecture to extract\n  -f, --files                   Extract File System files\n      --flat                    Do NOT perserve directory structure when extracting\n  -h, --help                    help for extract\n  -i, --iboot                   Extract iBoot\n      --insecure                do not verify ssl certs\n  -b, --kbag                    Extract Im4p Keybags\n  -k, --kernel                  Extract kernelcache\n  -o, --output string           Folder to extract files to\n      --pattern string          Extract files that match regex\n      --proxy string            HTTP/HTTPS proxy\n  -r, --remote                  Extract from URL\n  -s, --sep                     Extract sep-firmware\n")),(0,a.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre"},"      --color           colorize output\n      --config string   config file (default is $HOME/.ipsw/config.yaml)\n  -V, --verbose         verbose output\n")),(0,a.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,a.kt)("ul",null,(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw"},"ipsw"),"\t - Download and Parse IPSWs (and SO much more)")))}d.isMDXComponent=!0}}]);
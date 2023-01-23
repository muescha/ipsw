"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[3122],{3905:(e,r,t)=>{t.d(r,{Zo:()=>p,kt:()=>d});var n=t(7294);function i(e,r,t){return r in e?Object.defineProperty(e,r,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[r]=t,e}function o(e,r){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);r&&(n=n.filter((function(r){return Object.getOwnPropertyDescriptor(e,r).enumerable}))),t.push.apply(t,n)}return t}function c(e){for(var r=1;r<arguments.length;r++){var t=null!=arguments[r]?arguments[r]:{};r%2?o(Object(t),!0).forEach((function(r){i(e,r,t[r])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):o(Object(t)).forEach((function(r){Object.defineProperty(e,r,Object.getOwnPropertyDescriptor(t,r))}))}return e}function a(e,r){if(null==e)return{};var t,n,i=function(e,r){if(null==e)return{};var t,n,i={},o=Object.keys(e);for(n=0;n<o.length;n++)t=o[n],r.indexOf(t)>=0||(i[t]=e[t]);return i}(e,r);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(n=0;n<o.length;n++)t=o[n],r.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(i[t]=e[t])}return i}var s=n.createContext({}),l=function(e){var r=n.useContext(s),t=r;return e&&(t="function"==typeof e?e(r):c(c({},r),e)),t},p=function(e){var r=l(e.components);return n.createElement(s.Provider,{value:r},e.children)},h="mdxType",m={inlineCode:"code",wrapper:function(e){var r=e.children;return n.createElement(n.Fragment,{},r)}},f=n.forwardRef((function(e,r){var t=e.components,i=e.mdxType,o=e.originalType,s=e.parentName,p=a(e,["components","mdxType","originalType","parentName"]),h=l(t),f=i,d=h["".concat(s,".").concat(f)]||h[f]||m[f]||o;return t?n.createElement(d,c(c({ref:r},p),{},{components:t})):n.createElement(d,c({ref:r},p))}));function d(e,r){var t=arguments,i=r&&r.mdxType;if("string"==typeof e||i){var o=t.length,c=new Array(o);c[0]=f;var a={};for(var s in r)hasOwnProperty.call(r,s)&&(a[s]=r[s]);a.originalType=e,a[h]="string"==typeof e?e:i,c[1]=a;for(var l=2;l<o;l++)c[l]=t[l];return n.createElement.apply(null,c)}return n.createElement.apply(null,t)}f.displayName="MDXCreateElement"},7356:(e,r,t)=>{t.r(r),t.d(r,{assets:()=>s,contentTitle:()=>c,default:()=>h,frontMatter:()=>o,metadata:()=>a,toc:()=>l});var n=t(7462),i=(t(7294),t(3905));const o={id:"search",title:"search",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"search",description:"Find Mach-O files for given search criteria"},c=void 0,a={unversionedId:"cli/ipsw/macho/search",id:"cli/ipsw/macho/search",title:"search",description:"Find Mach-O files for given search criteria",source:"@site/docs/cli/ipsw/macho/search.md",sourceDirName:"cli/ipsw/macho",slug:"/cli/ipsw/macho/search",permalink:"/ipsw/docs/cli/ipsw/macho/search",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/macho/search.md",tags:[],version:"current",frontMatter:{id:"search",title:"search",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"search",description:"Find Mach-O files for given search criteria"},sidebar:"cli",previous:{title:"patch",permalink:"/ipsw/docs/cli/ipsw/macho/patch"},next:{title:"sign",permalink:"/ipsw/docs/cli/ipsw/macho/sign"}},s={},l=[{value:"ipsw macho search",id:"ipsw-macho-search",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],p={toc:l};function h(e){let{components:r,...t}=e;return(0,i.kt)("wrapper",(0,n.Z)({},p,t,{components:r,mdxType:"MDXLayout"}),(0,i.kt)("h2",{id:"ipsw-macho-search"},"ipsw macho search"),(0,i.kt)("p",null,"Find Mach-O files for given search criteria"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"ipsw macho search [flags]\n")),(0,i.kt)("h3",{id:"options"},"Options"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"  -g, --category string       Search for specific ObjC category\n  -c, --class string          Search for specific ObjC class\n  -h, --help                  help for search\n  -i, --ipsw string           Path to IPSW to scan for search criteria\n  -l, --load-command string   Search for specific load command\n  -p, --protocol string       Search for specific ObjC protocol\n")),(0,i.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"      --color           colorize output\n      --config string   config file (default is $HOME/.ipsw/config.yaml)\n  -V, --verbose         verbose output\n")),(0,i.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/macho"},"ipsw macho"),"\t - Parse MachO")))}h.isMDXComponent=!0}}]);
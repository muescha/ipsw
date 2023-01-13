"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[7936],{3905:(e,t,o)=>{o.d(t,{Zo:()=>p,kt:()=>w});var n=o(7294);function r(e,t,o){return t in e?Object.defineProperty(e,t,{value:o,enumerable:!0,configurable:!0,writable:!0}):e[t]=o,e}function i(e,t){var o=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),o.push.apply(o,n)}return o}function a(e){for(var t=1;t<arguments.length;t++){var o=null!=arguments[t]?arguments[t]:{};t%2?i(Object(o),!0).forEach((function(t){r(e,t,o[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(o)):i(Object(o)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(o,t))}))}return e}function l(e,t){if(null==e)return{};var o,n,r=function(e,t){if(null==e)return{};var o,n,r={},i=Object.keys(e);for(n=0;n<i.length;n++)o=i[n],t.indexOf(o)>=0||(r[o]=e[o]);return r}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)o=i[n],t.indexOf(o)>=0||Object.prototype.propertyIsEnumerable.call(e,o)&&(r[o]=e[o])}return r}var d=n.createContext({}),s=function(e){var t=n.useContext(d),o=t;return e&&(o="function"==typeof e?e(t):a(a({},t),e)),o},p=function(e){var t=s(e.components);return n.createElement(d.Provider,{value:t},e.children)},c="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},m=n.forwardRef((function(e,t){var o=e.components,r=e.mdxType,i=e.originalType,d=e.parentName,p=l(e,["components","mdxType","originalType","parentName"]),c=s(o),m=r,w=c["".concat(d,".").concat(m)]||c[m]||u[m]||i;return o?n.createElement(w,a(a({ref:t},p),{},{components:o})):n.createElement(w,a({ref:t},p))}));function w(e,t){var o=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var i=o.length,a=new Array(i);a[0]=m;var l={};for(var d in t)hasOwnProperty.call(t,d)&&(l[d]=t[d]);l.originalType=e,l[c]="string"==typeof e?e:r,a[1]=l;for(var s=2;s<i;s++)a[s]=o[s];return n.createElement.apply(null,a)}return n.createElement.apply(null,o)}m.displayName="MDXCreateElement"},3552:(e,t,o)=>{o.r(t),o.d(t,{assets:()=>d,contentTitle:()=>a,default:()=>c,frontMatter:()=>i,metadata:()=>l,toc:()=>s});var n=o(7462),r=(o(7294),o(3905));const i={id:"dev",title:"dev",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"dev",description:"Download IPSWs (and more) from https://developer.apple.com/download",last_update:{date:new Date("2023-01-13T18:46:22.000Z"),author:"blacktop"}},a=void 0,l={unversionedId:"cli/ipsw/download/dev",id:"cli/ipsw/download/dev",title:"dev",description:"Download IPSWs (and more) from https://developer.apple.com/download",source:"@site/docs/cli/ipsw/download/dev.md",sourceDirName:"cli/ipsw/download",slug:"/cli/ipsw/download/dev",permalink:"/ipsw/docs/cli/ipsw/download/dev",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/download/dev.md",tags:[],version:"current",frontMatter:{id:"dev",title:"dev",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"dev",description:"Download IPSWs (and more) from https://developer.apple.com/download",last_update:{date:"2023-01-13T18:46:22.000Z",author:"blacktop"}},sidebar:"cli",previous:{title:"download",permalink:"/ipsw/docs/cli/ipsw/download/"},next:{title:"git",permalink:"/ipsw/docs/cli/ipsw/download/git"}},d={},s=[{value:"ipsw download dev",id:"ipsw-download-dev",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],p={toc:s};function c(e){let{components:t,...o}=e;return(0,r.kt)("wrapper",(0,n.Z)({},p,o,{components:t,mdxType:"MDXLayout"}),(0,r.kt)("h2",{id:"ipsw-download-dev"},"ipsw download dev"),(0,r.kt)("p",null,"Download IPSWs (and more) from ",(0,r.kt)("a",{parentName:"p",href:"https://developer.apple.com/download"},"https://developer.apple.com/download")),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre"},"ipsw download dev [flags]\n")),(0,r.kt)("h3",{id:"options"},"Options"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre"},"  -h, --help                    help for dev\n      --json                    Output downloadable items as JSON\n      --more                    Download 'More' OSes/Apps\n      --os                      Download '*OS' OSes/Apps\n  -o, --output string           Folder to download files to\n  -p, --page int                Page size for file lists (default 20)\n      --pretty                  Pretty print JSON\n      --sms                     Prefer SMS Two-factor authentication\n  -k, --vault-password string   Password to unlock credential vault (only for file vaults)\n  -w, --watch stringArray       Developer portal group pattern to watch (i.e. '^iOS.*beta$')\n")),(0,r.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre"},"      --black-list stringArray   iOS device black list\n  -b, --build string             iOS BuildID (i.e. 16F203)\n      --color                    colorize output\n      --config string            config file (default is $HOME/.ipsw/config.yaml)\n  -y, --confirm                  do not prompt user for confirmation\n  -d, --device string            iOS Device (i.e. iPhone11,2)\n      --insecure                 do not verify ssl certs\n  -m, --model string             iOS Model (i.e. D321AP)\n      --proxy string             HTTP/HTTPS proxy\n  -_, --remove-commas            replace commas in IPSW filename with underscores\n      --restart-all              always restart resumable IPSWs\n      --resume-all               always resume resumable IPSWs\n      --skip-all                 always skip resumable IPSWs\n  -V, --verbose                  verbose output\n  -v, --version string           iOS Version (i.e. 12.3.1)\n      --white-list stringArray   iOS device white list\n")),(0,r.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/download"},"ipsw download"),"\t - Download Apple Firmware files (and more)")))}c.isMDXComponent=!0}}]);
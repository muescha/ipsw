"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[5075],{3905:(e,t,a)=>{a.d(t,{Zo:()=>m,kt:()=>h});var i=a(7294);function r(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}function n(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);t&&(i=i.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,i)}return a}function s(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?n(Object(a),!0).forEach((function(t){r(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):n(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function l(e,t){if(null==e)return{};var a,i,r=function(e,t){if(null==e)return{};var a,i,r={},n=Object.keys(e);for(i=0;i<n.length;i++)a=n[i],t.indexOf(a)>=0||(r[a]=e[a]);return r}(e,t);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);for(i=0;i<n.length;i++)a=n[i],t.indexOf(a)>=0||Object.prototype.propertyIsEnumerable.call(e,a)&&(r[a]=e[a])}return r}var o=i.createContext({}),c=function(e){var t=i.useContext(o),a=t;return e&&(a="function"==typeof e?e(t):s(s({},t),e)),a},m=function(e){var t=c(e.components);return i.createElement(o.Provider,{value:t},e.children)},p="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return i.createElement(i.Fragment,{},t)}},u=i.forwardRef((function(e,t){var a=e.components,r=e.mdxType,n=e.originalType,o=e.parentName,m=l(e,["components","mdxType","originalType","parentName"]),p=c(a),u=r,h=p["".concat(o,".").concat(u)]||p[u]||d[u]||n;return a?i.createElement(h,s(s({ref:t},m),{},{components:a})):i.createElement(h,s({ref:t},m))}));function h(e,t){var a=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var n=a.length,s=new Array(n);s[0]=u;var l={};for(var o in t)hasOwnProperty.call(t,o)&&(l[o]=t[o]);l.originalType=e,l[p]="string"==typeof e?e:r,s[1]=l;for(var c=2;c<n;c++)s[c]=a[c];return i.createElement.apply(null,s)}return i.createElement.apply(null,a)}u.displayName="MDXCreateElement"},3208:(e,t,a)=>{a.r(t),a.d(t,{assets:()=>o,contentTitle:()=>s,default:()=>p,frontMatter:()=>n,metadata:()=>l,toc:()=>c});var i=a(7462),r=(a(7294),a(3905));const n={},s="Roadmap",l={unversionedId:"roadmap",id:"roadmap",title:"Roadmap",description:"I'd like to get to a 1-to-1 feature match with jtool2 (\u2705 DONE)",source:"@site/docs/roadmap.md",sourceDirName:".",slug:"/roadmap",permalink:"/ipsw/docs/roadmap",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/roadmap.md",tags:[],version:"current",frontMatter:{},sidebar:"docs",previous:{title:"PongoOS",permalink:"/ipsw/docs/guides/pongo"}},o={},c=[{value:"TODO",id:"todo",level:3}],m={toc:c};function p(e){let{components:t,...a}=e;return(0,r.kt)("wrapper",(0,i.Z)({},m,a,{components:t,mdxType:"MDXLayout"}),(0,r.kt)("h1",{id:"roadmap"},"Roadmap"),(0,r.kt)("p",null,"I'd like to get to a 1-to-1 feature match with ",(0,r.kt)("inlineCode",{parentName:"p"},"jtool2")," ",(0,r.kt)("em",{parentName:"p"},"(\u2705 DONE)")),(0,r.kt)("p",null,"My main goal is to create a mantainable ",(0,r.kt)("em",{parentName:"p"},"dyld_shared_cache")," splitter"),(0,r.kt)("p",null,"My strech goal is to make the worlds first ",(0,r.kt)("em",{parentName:"p"},"dyld_shared_cache")," disassembler that doesn't take days/a super computer \ud83d\ude0f to analyze"),(0,r.kt)("h3",{id:"todo"},"TODO"),(0,r.kt)("ul",{className:"contains-task-list"},(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!1,disabled:!0})," ","MachO read/write"),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!1,disabled:!0})," ","pure Go dyld splitter"),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!1,disabled:!0})," ","APFS/HFS parsing to pull dyld without mounting"),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!0,disabled:!0})," ","(jtool) -K Kextract\u2122 a kernel extension by its bundle ID ",(0,r.kt)("em",{parentName:"li"},"(only MH_FILESETS for now)")),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!1,disabled:!0})," ","watch for new IPSW files with ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/radovskyb/watcher"},"https://github.com/radovskyb/watcher")),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!1,disabled:!0})," ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/xerub/img4lib"},"https://github.com/xerub/img4lib")," and ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/tihmstar/img4tool"},"https://github.com/tihmstar/img4tool")),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!1,disabled:!0})," ","devicetree read/write"),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!1,disabled:!0})," ","add \ud83d\udc84",(0,r.kt)("a",{parentName:"li",href:"https://github.com/muesli/termenv"},"https://github.com/muesli/termenv")),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!1,disabled:!0})," ","maybe use ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/AllenDang/giu"},"https://github.com/AllenDang/giu")," for disassembler"),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!0,disabled:!0})," ","add ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/mermaid-js/mermaid"},"https://github.com/mermaid-js/mermaid")," to docs"),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!1,disabled:!0})," ","API maybe use (github.com/minio/simdjson-go)"),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!0,disabled:!0})," ","Switch docs to ",(0,r.kt)("a",{parentName:"li",href:"https://squidfunk.github.io/mkdocs-material/getting-started/"},"https://squidfunk.github.io/mkdocs-material/getting-started/")," ",(0,r.kt)("em",{parentName:"li"},"(used docusaurus)")),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!0,disabled:!0})," ","store download dev session or creds using - ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/keybase/go-keychain"},"https://github.com/keybase/go-keychain")," ",(0,r.kt)("em",{parentName:"li"},"(used github.com/99designs/keyring as it offers multi-arch solutions)")),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!1,disabled:!0})," ","speed up downloads w/ ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/ynsgnr/aria2go"},"https://github.com/ynsgnr/aria2go")),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!1,disabled:!0})," ","make a color syntax highlighter like ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/trishume/syntect"},"https://github.com/trishume/syntect")," but for Golang"),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!0,disabled:!0})," ","use ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/google/gousb"},"https://github.com/google/gousb")," to detect what device(s) are connected (maybe filter downloads?)"),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!1,disabled:!0})," ","replace cgo sqlite w/ ",(0,r.kt)("a",{parentName:"li",href:"https://pkg.go.dev/modernc.org/sqlite"},"https://pkg.go.dev/modernc.org/sqlite")),(0,r.kt)("li",{parentName:"ul",className:"task-list-item"},(0,r.kt)("input",{parentName:"li",type:"checkbox",checked:!1,disabled:!0})," ","emulator ideas: ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/containers/podman/tree/main/pkg/machine/qemu"},"qemu"),", ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/digitalocean/go-qemu"},"qemu"),", ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/lxc/lxd"},"lxd"),", ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/TrungNguyen1909/qemu-t8030"},"qemu-t8030"))))}p.isMDXComponent=!0}}]);
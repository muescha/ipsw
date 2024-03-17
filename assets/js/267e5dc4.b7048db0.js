"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[1817],{42540:(e,s,n)=>{n.r(s),n.d(s,{assets:()=>d,contentTitle:()=>i,default:()=>u,frontMatter:()=>r,metadata:()=>c,toc:()=>l});var o=n(74848),t=n(28453);const r={description:"Dumping shsh blobs allows you to downgrade iOS later."},i="Dump SHSH Blobs",c={id:"guides/shsh",title:"Dump SHSH Blobs",description:"Dumping shsh blobs allows you to downgrade iOS later.",source:"@site/docs/guides/shsh.md",sourceDirName:"guides",slug:"/guides/shsh",permalink:"/ipsw/docs/guides/shsh",draft:!1,unlisted:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/guides/shsh.md",tags:[],version:"current",frontMatter:{description:"Dumping shsh blobs allows you to downgrade iOS later."},sidebar:"docs",previous:{title:"List *OS Devices",permalink:"/ipsw/docs/guides/device_list"},next:{title:"Prep device for remote debugging",permalink:"/ipsw/docs/guides/debugserver"}},d={},l=[];function a(e){const s={a:"a",blockquote:"blockquote",code:"code",h1:"h1",p:"p",pre:"pre",...(0,t.R)(),...e.components};return(0,o.jsxs)(o.Fragment,{children:[(0,o.jsx)(s.h1,{id:"dump-shsh-blobs",children:"Dump SHSH Blobs"}),"\n",(0,o.jsxs)(s.blockquote,{children:["\n",(0,o.jsx)(s.p,{children:"Dumping shsh blobs allows you to downgrade iOS later."}),"\n"]}),"\n",(0,o.jsxs)(s.p,{children:[(0,o.jsx)(s.a,{href:"https://checkra.in/",children:"Jailbreak"})," your iDevice and install openssh"]}),"\n",(0,o.jsx)(s.pre,{children:(0,o.jsx)(s.code,{className:"language-bash",children:"\u276f ipsw idev proxy --lport 2222 --rport 22\n   \u2022 Connecting proxy to device lport=2222 rport=22\n"})}),"\n",(0,o.jsx)(s.pre,{children:(0,o.jsx)(s.code,{className:"language-bash",children:"\u276f ipsw shsh\n\n   \u2022 Connecting to root@localhost:2222\n      \u2022 Parsing shsh\n      \u2022 Parsing IMG4\n         \u2022 Dumped SHSH blob to 1249767383957670.dumped.shsh\n"})})]})}function u(e={}){const{wrapper:s}={...(0,t.R)(),...e.components};return s?(0,o.jsx)(s,{...e,children:(0,o.jsx)(a,{...e})}):a(e)}},28453:(e,s,n)=>{n.d(s,{R:()=>i,x:()=>c});var o=n(96540);const t={},r=o.createContext(t);function i(e){const s=o.useContext(r);return o.useMemo((function(){return"function"==typeof e?e(s):{...s,...e}}),[s,e])}function c(e){let s;return s=e.disableParentContext?"function"==typeof e.components?e.components(t):e.components||t:i(e.components),o.createElement(r.Provider,{value:s},e.children)}}}]);
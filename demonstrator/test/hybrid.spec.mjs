import { test, expect, open, layoutProblems } from './helpers.mjs';

test.use({ viewport: { width: 1920, height: 1000 } });

for (const variant of ['phs', 'pta', 'federation']) {
  test(`hybrid sign-in: ${variant} keeps the Entra OAuth contract`, async ({ page }) => {
    await open(page, `#flow/hybrid-signin?variant=${variant}`);
    const result = await page.evaluate(() => {
      const p = APP.player, steps = p.steps;
      const access = steps.find((s) => s.id === 'hy-authorize').tokens.find((t) => t.name === 'AT');
      const tokenRequest = steps.find((s) => s.id === 'hy-token-req').req;
      return {
        actorsKnown: steps.every((s) => ACTORS[s.from] && ACTORS[s.to] && p.flow.actors.includes(s.from) && p.flow.actors.includes(s.to)),
        uniqueIds: new Set(steps.map((s) => s.id)).size === steps.length,
        unresolved: /\{\{\w+\}\}/.test(JSON.stringify(steps)),
        issuer: access.payload.iss, expectedIssuer: ISS_V2,
        audience: access.payload.aud, expectedAudience: ID.api.appId,
        subject: access.payload.oid, expectedSubject: ID.user.oid,
        grant: tokenRequest.form.grant_type, verifier: tokenRequest.form.code_verifier,
        challenge: steps.find((s) => s.id === 'hy-authz').req.query.code_challenge,
        mfaBeforeCode: steps.findIndex((s) => s.id === 'hy-mfa') < steps.findIndex((s) => s.id === 'hy-code'),
        authorization: stepStages(steps.find((s) => s.id === 'hy-authorize')),
        federation: steps.some((s) => s.id === 'hy-assertion'),
        agent: steps.some((s) => s.id === 'hy-result'),
        exported: JSON.stringify(scrubDeep(steps)),
      };
    });
    expect(result.actorsKnown).toBe(true);
    expect(result.uniqueIds).toBe(true);
    expect(result.unresolved).toBe(false);
    expect(result.issuer).toBe(result.expectedIssuer);
    expect(result.audience).toBe(result.expectedAudience);
    expect(result.subject).toBe(result.expectedSubject);
    expect(result.grant).toBe('authorization_code');
    expect(result.verifier).toHaveLength(64);
    expect(result.challenge).toHaveLength(43);
    expect(result.mfaBeforeCode).toBe(true);
    expect(result.authorization).toEqual(['validate', 'authorize']);
    expect(result.federation).toBe(variant === 'federation');
    expect(result.agent).toBe(variant === 'pta');
    expect(result.exported).not.toMatch(/eyJ[\w-]*\.[\w-]+\.[\w-]+/);
    await page.evaluate(() => APP.player.goTo(APP.player.steps.length - 1));
    await expect(page.locator('#inspector .recap')).toBeVisible();
  });
}

test('PTA outage issues neither a code nor a token and explains manual recovery', async ({ page }) => {
  await open(page, '#flow/hybrid-signin?variant=pta-outage');
  const result = await page.evaluate(() => ({
    steps: APP.player.steps.map((s) => s.id),
    tokens: APP.player.steps.flatMap((s) => s.tokens),
    end: APP.player.steps.at(-1),
  }));
  expect(result.steps).not.toContain('hy-code');
  expect(result.steps).not.toContain('hy-token-res');
  expect(result.tokens).toEqual([]);
  expect(result.end.status).toBe('error');
  expect(result.end.kv.recovery).toContain('Manually');
  expect(result.end.desc).toContain('no automatic fallback');
});

for (const variant of ['published', 'denied', 'direct']) {
  test(`on-premises app: ${variant} respects the MFA / Kerberos boundary`, async ({ page }) => {
    await open(page, `#flow/onprem-app-proxy?variant=${variant}`);
    const result = await page.evaluate(() => {
      const steps = APP.player.steps;
      return {
        ids: steps.map((s) => s.id),
        knownActors: steps.every((s) => ACTORS[s.from] && ACTORS[s.to]),
        tokens: steps.flatMap((s) => s.tokens),
        backend: steps.find((s) => s.id === (APP.player.variant === 'direct' ? 'op-direct-ticket' : 'op-backend')).req,
        validation: stepStages(steps.find((s) => s.id === 'op-validate')),
        authorization: steps.find((s) => s.id === 'op-authorize'),
        ticketStages: stepStages(steps.find((s) => s.id === (APP.player.variant === 'direct' ? 'op-service' : 'op-ticket'))),
        final: steps.at(-1),
      };
    });
    expect(result.knownActors).toBe(true);
    expect(result.tokens).toEqual([]);
    expect(result.backend.headers.Authorization).toBe('Negotiate <Kerberos service ticket>');
    expect(result.validation).toEqual(['validate']);
    expect(result.ticketStages).toEqual(['issue']);
    expect(result.authorization.det).toBe('resource');
    expect(result.authorization.checks[0].ok).toBe(variant !== 'denied');
    expect(result.final.res.status).toBe(variant === 'denied' ? 403 : 200);
    if (variant === 'direct') {
      expect(result.ids).not.toContain('op-mfa');
      expect(result.ids).not.toContain('op-kcd');
      expect(result.final.kv.entraConditionalAccess).toBe('Not invoked');
    } else {
      expect(result.ids).toContain('op-mfa');
      expect(result.ids).toContain('op-kcd');
    }
    await page.evaluate(() => APP.player.goTo(APP.player.steps.length - 1));
    if (variant === 'denied') await expect(page.locator('#inspector .recap')).toContainText('Intranet web app');
  });
}

test('hybrid device separates AD logon, cloud PRT, compliance and MFA', async ({ page }) => {
  await open(page, '#flow/device-sso?variant=hybrid');
  const result = await page.evaluate(() => {
    const steps = APP.player.steps;
    return {
      ids: steps.map((s) => s.id),
      prtStage: stepStages(steps.find((s) => s.id === 'dv-hy-prt-res')),
      compliance: steps.find((s) => s.id === 'dv-hy-policy').checks.map((c) => c.name),
      token: steps.find((s) => s.id === 'dv-hy-token').tokens[0].payload,
    };
  });
  expect(result.ids.indexOf('dv-hy-tgt')).toBeLessThan(result.ids.indexOf('dv-hy-prt-req'));
  expect(result.ids.indexOf('dv-hy-mfa')).toBeLessThan(result.ids.indexOf('dv-hy-token'));
  expect(result.prtStage).toEqual(['issue']);
  expect(result.compliance).toEqual(['Entra hybrid device identity presented', 'Device compliant in Intune', 'MFA requirement satisfied']);
  expect(result.token.deviceid).toBeTruthy();
  expect(result.token.scp).toBe('User.Read');
});

test('AD-only device passes MFA but cannot satisfy cloud compliance', async ({ page }) => {
  await open(page, '#flow/device-sso?variant=ad-only');
  const result = await page.evaluate(() => ({
    tokens: APP.player.steps.flatMap((s) => s.tokens),
    final: APP.player.steps.at(-1),
  }));
  expect(result.tokens).toEqual([]);
  expect(result.final.status).toBe('error');
  expect(result.final.checks.map((c) => c.ok)).toEqual([true, false, false]);
  expect(result.final.res.json.error_description).toContain('AADSTS53000');
});

test('hybrid additions are simulated only; existing device variants retain live support', async ({ page }) => {
  await open(page, '#flow/device-sso');
  const result = await page.evaluate(() => {
    Live.ready = () => true;
    return {
      variants: APP.player.flow.variants.map((v) => {
        APP.player.variant = v.id;
        return [v.id, APP.player.canRunLive()];
      }),
      newFlows: ['hybrid-signin', 'onprem-app-proxy'].map((id) => FLOWS.find((f) => f.id === id).live),
      links: ['hybrid-signin', 'onprem-app-proxy', 'device-sso'].every((id) => DOC_LINKS[id].every((link) => link?.length === 2 && link[1].startsWith('https://'))),
    };
  });
  expect(result.variants).toEqual([['managed', true], ['unknown', true], ['hybrid', false], ['ad-only', false]]);
  expect(result.newFlows).toEqual([false, false]);
  expect(result.links).toBe(true);
});

test('on-premises actors appear in every architecture layout', async ({ page }) => {
  await open(page, '#architecture');
  for (const view of ['columns', 'bowtie', 'hub']) {
    await page.locator(`#archTab-${view}`).click();
    for (const actor of ['sync', 'authAgent', 'adfs', 'appProxy', 'proxyConnector', 'legacyWeb']) {
      await expect(page.locator(`#archSvg .node[data-actor="${actor}"]`)).toHaveCount(1);
    }
    expect(await layoutProblems(page)).toEqual([]);
  }
});

test.describe('on-premises variants at browser zoom', () => {
  test.use({ viewport: { width: 911, height: 467 }, deviceScaleFactor: 1.5 });
  test('every variant remains readable in both diagram views', async ({ page }) => {
    for (const [flow, variants] of [
      ['hybrid-signin', ['phs', 'pta', 'federation', 'pta-outage']],
      ['onprem-app-proxy', ['published', 'denied', 'direct']],
      ['device-sso', ['hybrid', 'ad-only']],
    ]) {
      for (const variant of variants) {
        await open(page, `#flow/${flow}?variant=${variant}`);
        for (const view of ['diagram', 'sequence']) {
          await page.evaluate((v) => {
            APP.player.setView(v);
            APP.player.goTo(APP.player.steps.length - 1);
            APP.player.syncLayout();
            APP.player.zoom.apply();
          }, view);
          expect(await layoutProblems(page), `${flow}/${variant}/${view}`).toEqual([]);
        }
      }
    }
  });
});

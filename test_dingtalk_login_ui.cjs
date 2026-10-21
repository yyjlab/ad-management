// Run with node --test test_dingtalk_login_ui.cjs. No network or browser is used.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const html = fs.readFileSync(path.join(__dirname, 'admin_login.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const redirectUri = 'http://ad.wfq.test/api/admin/dingtalk/callback';
const state = 's'.repeat(43);

function fixture() {
    const navigations = [];
    const listeners = new Map();
    const frame = {contentWindow: {}};
    const actions = {hidden: true};
    const authorization = {redirectUri, state, expiresAt: Date.now() + 60000};
    const context = vm.createContext({
        URL, URLSearchParams, authorization,
        location: new URL('http://ad.wfq.test/admin'),
        document: {getElementById: id => id === 'dingtalkFrame' ? frame : actions},
        fetch: async url => {
            assert.equal(url, '/api/admin/dingtalk/status');
            return {json: async () => ({enabled: true})};
        },
        window: {
            addEventListener: (name, handler) => listeners.set(name, handler),
            location: {assign: url => navigations.push(url)}
        }
    });
    vm.runInContext(script, context, {filename: 'admin_login.html'});
    vm.runInContext('dingtalkAuthorization = authorization;', context);
    return {
        navigations, authorization,
        send(params, overrides = {}) {
            listeners.get('message')({
                origin: 'https://login.dingtalk.com', source: frame.contentWindow,
                data: {success: true, redirectUrl: redirectUri + '?' + new URLSearchParams({state}) + '&' + new URLSearchParams(params)},
                ...overrides
            });
        }
    };
}

test('QR callback accepts either alias and prefers authCode when both are present', () => {
    const cases = [
        [[['authCode', 'auth-code']], 'auth-code'],
        [[['code', 'fallback-code']], 'fallback-code'],
        [[['code', 'same-code'], ['authCode', 'same-code']], 'same-code'],
        [[['code', 'other-code'], ['authCode', 'auth-code']], 'auth-code']
    ];
    for (const [params, expected] of cases) {
        const page = fixture();
        page.send(params);
        assert.deepEqual(page.navigations, ['/api/admin/dingtalk/callback?' + new URLSearchParams({authCode: expected, state})]);
        page.send(params);
        assert.equal(page.navigations.length, 1, 'authorization must be consumed once');
    }
});

test('QR callback rejects duplicate names, invalid selected code, denial and duplicate state', () => {
    const cases = [
        [],
        [['authCode', 'one'], ['authCode', 'two']],
        [['code', 'one'], ['code', 'two']],
        [['authCode', 'valid'], ['code', 'same'], ['code', 'same']],
        [['authCode', 'same'], ['authCode', 'same'], ['code', 'valid']],
        [['authCode', ''], ['code', 'valid']],
        [['authCode', ' '], ['code', 'valid']],
        [['authCode', 'x'.repeat(2049)], ['code', 'valid']],
        [['code', '']],
        [['code', ' ']],
        [['code', 'x'.repeat(2049)]],
        [['authCode', 'valid'], ['code', 'other'], ['error', 'access_denied']],
        [['authCode', 'valid'], ['code', 'other'], ['state', state]]
    ];
    for (const params of cases) {
        const page = fixture();
        page.send(params);
        assert.equal(page.navigations.length, 0);
    }
});

test('QR callback retains origin, frame, callback URL, state and expiry validation', () => {
    const callback = redirectUri + '?' + new URLSearchParams({authCode: 'valid', code: 'other', state});
    const cases = [
        {origin: 'https://untrusted.test'},
        {source: {}},
        {data: {success: false, redirectUrl: callback}},
        {data: {success: true, redirectUrl: callback.replace('ad.wfq.test', 'untrusted.test')}},
        {data: {success: true, redirectUrl: callback.replace('/callback', '/login')}},
        {data: {success: true, redirectUrl: callback.replace('http://', 'http://user:password@')}},
        {data: {success: true, redirectUrl: callback + '#fragment'}},
        {data: {success: true, redirectUrl: callback.replace(state, 'wrong-state')}},
        {data: {success: true, redirectUrl: callback.replace('&state=' + state, '')}}
    ];
    for (const overrides of cases) {
        const page = fixture();
        page.send([], overrides);
        assert.equal(page.navigations.length, 0);
    }
    const expired = fixture();
    expired.authorization.expiresAt = Date.now() - 1;
    expired.send([['authCode', 'valid'], ['code', 'other']]);
    assert.equal(expired.navigations.length, 0);
});

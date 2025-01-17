/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

import { module, test } from 'qunit';
import { setupApplicationTest } from 'ember-qunit';
import { setupMirage } from 'ember-cli-mirage/test-support';
import syncHandler from 'vault/mirage/handlers/sync';
import { CONFIG_RESPONSE, STATIC_NOW } from 'vault/mirage/handlers/clients';
import { visit, click, currentURL } from '@ember/test-helpers';
import sinon from 'sinon';
import timestamp from 'core/utils/timestamp';
import authPage from 'vault/tests/pages/auth';
import { SELECTORS } from 'vault/tests/helpers/clients';

module('Acceptance | clients | sync | activated', function (hooks) {
  setupApplicationTest(hooks);
  setupMirage(hooks);

  hooks.before(function () {
    sinon.stub(timestamp, 'now').callsFake(() => STATIC_NOW);
  });

  hooks.beforeEach(async function () {
    syncHandler(this.server);
    await authPage.login();
    return visit('/vault/clients/counts/sync');
  });

  hooks.after(function () {
    timestamp.now.restore();
  });

  test('it should render charts when secrets sync is activated', async function (assert) {
    syncHandler(this.server);

    assert.dom(SELECTORS.charts.chart('Secrets sync usage')).exists('Secrets sync usage chart is rendered');
    assert.dom(SELECTORS.syncTab.total).exists('Total sync clients chart is rendered');
    assert.dom(SELECTORS.emptyStateTitle).doesNotExist();
  });
});

module('Acceptance | clients | sync | not activated', function (hooks) {
  setupApplicationTest(hooks);
  setupMirage(hooks);

  hooks.before(function () {
    sinon.stub(timestamp, 'now').callsFake(() => STATIC_NOW);
  });

  hooks.beforeEach(async function () {
    this.server.get('/sys/internal/counters/config', function () {
      return CONFIG_RESPONSE;
    });
    await authPage.login();
    return visit('/vault/clients/counts/sync');
  });

  hooks.after(function () {
    timestamp.now.restore();
  });

  test('it should show an empty state when secrets sync is not activated', async function (assert) {
    assert.expect(3);

    // ensure secret_syncs clients activity is 0
    this.server.get('/sys/internal/counters/activity', () => {
      // return only the things that determine whether to show/hide secrets sync
      return {
        data: {
          total: {
            secret_syncs: 0,
          },
        },
      };
    });

    this.server.get('/sys/activation-flags', () => {
      assert.true(true, '/sys/activation-flags/ is called to check if secrets-sync is activated');

      return {
        data: {
          activated: [],
          unactivated: ['secrets-sync'],
        },
      };
    });

    assert.dom(SELECTORS.emptyStateTitle).exists('Shows empty state when secrets-sync is not activated');

    await click(`${SELECTORS.emptyStateActions} .hds-link-standalone`);
    assert.strictEqual(
      currentURL(),
      '/vault/sync/secrets/overview',
      'action button navigates to secrets sync overview page'
    );
  });
});

/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

import { alias, equal } from '@ember/object/computed';
import Service, { inject as service } from '@ember/service';
import { task } from 'ember-concurrency';
import { computed } from '@ember/object';
import { getRelativePath } from 'core/utils/sanitize-path';
import { buildWaiter } from '@ember/test-waiters';

const waiter = buildWaiter('namespaces');
const ROOT_NAMESPACE = '';
export default Service.extend({
  store: service(),
  auth: service(),
  userRootNamespace: alias('auth.authData.userRootNamespace'),
  //populated by the query param on the cluster route
  path: '',
  // list of namespaces available to the current user under the
  // current namespace
  accessibleNamespaces: null,

  inRootNamespace: equal('path', ROOT_NAMESPACE),

  currentNamespace: computed('inRootNamespace', 'path', function () {
    if (this.inRootNamespace) return 'root';

    const parts = this.path?.split('/');
    return parts[parts.length - 1];
  }),

  relativeNamespace: computed('path', 'userRootNamespace', function () {
    // relative namespace is the current namespace minus the user's root.
    // so if we're in app/staging/group1 but the user's root is app, the
    // relative namespace is staging/group
    return getRelativePath(this.path, this.userRootNamespace);
  }),

  setNamespace(path) {
    if (!path) {
      this.set('path', '');
      return;
    }
    this.set('path', path);
  },

  findNamespacesForUser: task(function* () {
    const waiterToken = waiter.beginAsync();
    // uses the adapter and the raw response here since
    // models get wiped when switching namespaces and we
    // want to keep track of these separately
    const store = this.store;
    const adapter = store.adapterFor('namespace');
    const userRoot = this.auth.authData.userRootNamespace;
    try {
      const ns = yield adapter.findAll(store, 'namespace', null, {
        adapterOptions: {
          forUser: true,
          namespace: userRoot,
        },
      });
      const keys = ns.data.keys || [];
      this.set(
        'accessibleNamespaces',
        keys.map((n) => {
          let fullNS = n;
          // if the user's root isn't '', then we need to construct
          // the paths so they connect to the user root to the list
          // otherwise using the current ns to grab the correct leaf
          // node in the graph doesn't work
          if (userRoot) {
            fullNS = `${userRoot}/${n}`;
          }
          return fullNS.replace(/\/$/, '');
        })
      );
    } catch (e) {
      //do nothing here
    } finally {
      waiter.endAsync(waiterToken);
    }
  }).drop(),

  reset() {
    this.set('accessibleNamespaces', null);
  },
});

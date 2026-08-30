CREATE TABLE authority_keys (
    key_id BLOB PRIMARY KEY
        CHECK(typeof(key_id) = 'blob' AND length(key_id) = 32),
    role TEXT NOT NULL
        CHECK(typeof(role) = 'text' AND role IN ('owner','recovery')),
    permission_mask INTEGER NOT NULL
        CHECK(typeof(permission_mask) = 'integer'
          AND permission_mask IN (7,8)
          AND ((role = 'owner' AND permission_mask = 7)
            OR (role = 'recovery' AND permission_mask = 8))),
    public_key BLOB NOT NULL UNIQUE
        CHECK(typeof(public_key) = 'blob' AND length(public_key) = 32),
    state TEXT NOT NULL
        CHECK(typeof(state) = 'text'
          AND state IN ('staged','active','retired','revoked')),
    valid_from_epoch INTEGER NOT NULL
        CHECK(typeof(valid_from_epoch) = 'integer' AND valid_from_epoch > 0),
    valid_to_epoch INTEGER
        CHECK(valid_to_epoch IS NULL OR
          (typeof(valid_to_epoch) = 'integer' AND valid_to_epoch >= valid_from_epoch)),
    installed_at INTEGER NOT NULL
        CHECK(typeof(installed_at) = 'integer' AND installed_at >= 0),
    retired_at INTEGER
        CHECK(retired_at IS NULL OR (typeof(retired_at) = 'integer' AND retired_at >= installed_at)),
    CHECK((state IN ('staged','active') AND valid_to_epoch IS NULL AND retired_at IS NULL)
       OR (state IN ('retired','revoked') AND valid_to_epoch IS NOT NULL AND retired_at IS NOT NULL)),
    UNIQUE(key_id, role, permission_mask)
) STRICT;

CREATE UNIQUE INDEX authority_keys_one_active_role
ON authority_keys(role) WHERE state = 'active';
CREATE UNIQUE INDEX authority_keys_one_staged_role
ON authority_keys(role) WHERE state = 'staged';

CREATE TRIGGER authority_keys_identity_immutable
BEFORE UPDATE OF key_id, role, permission_mask, public_key, valid_from_epoch
ON authority_keys
WHEN NEW.key_id <> OLD.key_id
  OR NEW.role <> OLD.role
  OR NEW.permission_mask <> OLD.permission_mask
  OR NEW.public_key <> OLD.public_key
  OR NEW.valid_from_epoch <> OLD.valid_from_epoch
BEGIN
    SELECT RAISE(ABORT, 'authority key identity is immutable');
END;

CREATE TABLE trust_epochs (
    epoch INTEGER PRIMARY KEY
        CHECK(typeof(epoch) = 'integer' AND epoch > 0),
    owner_key_id BLOB NOT NULL
        CHECK(typeof(owner_key_id) = 'blob' AND length(owner_key_id) = 32),
    recovery_key_id BLOB NOT NULL
        CHECK(typeof(recovery_key_id) = 'blob' AND length(recovery_key_id) = 32),
    bundle_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(bundle_sha256) = 'blob' AND length(bundle_sha256) = 32),
    state TEXT NOT NULL
        CHECK(typeof(state) = 'text' AND state IN ('staged','active','retired')),
    predecessor_epoch INTEGER
        CHECK(predecessor_epoch IS NULL OR
          (typeof(predecessor_epoch) = 'integer' AND predecessor_epoch > 0
           AND predecessor_epoch < 9223372036854775807
           AND epoch = predecessor_epoch + 1)),
    rotation_kind TEXT
        CHECK(rotation_kind IS NULL OR
          (typeof(rotation_kind) = 'text'
           AND rotation_kind IN ('owner_rotate','recovery_rotate','owner_recover'))),
    transition_receipt_id BLOB
        CHECK(transition_receipt_id IS NULL OR
          (typeof(transition_receipt_id) = 'blob' AND length(transition_receipt_id) = 16)),
    new_owner_key_proof BLOB
        CHECK(new_owner_key_proof IS NULL OR
          (typeof(new_owner_key_proof) = 'blob' AND length(new_owner_key_proof) = 64)),
    new_recovery_key_proof BLOB
        CHECK(new_recovery_key_proof IS NULL OR
          (typeof(new_recovery_key_proof) = 'blob' AND length(new_recovery_key_proof) = 64)),
    staged_at INTEGER NOT NULL
        CHECK(typeof(staged_at) = 'integer' AND staged_at >= 0),
    activated_at INTEGER
        CHECK(activated_at IS NULL OR
          (typeof(activated_at) = 'integer' AND activated_at >= staged_at)),
    retired_at INTEGER
        CHECK(retired_at IS NULL OR
          (typeof(retired_at) = 'integer' AND activated_at IS NOT NULL
           AND retired_at >= activated_at)),
    CHECK(owner_key_id <> recovery_key_id),
    CHECK((predecessor_epoch IS NULL AND epoch = 1 AND state = 'active'
           AND rotation_kind IS NULL AND transition_receipt_id IS NULL
           AND new_owner_key_proof IS NULL AND new_recovery_key_proof IS NULL
           AND activated_at IS NOT NULL AND retired_at IS NULL)
       OR (predecessor_epoch IS NOT NULL AND epoch > 1 AND rotation_kind IS NOT NULL
           AND transition_receipt_id IS NOT NULL
           AND ((rotation_kind = 'owner_rotate' AND new_owner_key_proof IS NOT NULL
                 AND new_recovery_key_proof IS NULL)
             OR (rotation_kind = 'recovery_rotate' AND new_owner_key_proof IS NULL
                 AND new_recovery_key_proof IS NOT NULL)
             OR (rotation_kind = 'owner_recover' AND new_owner_key_proof IS NOT NULL
                 AND new_recovery_key_proof IS NOT NULL)))),
    CHECK((state = 'staged' AND activated_at IS NULL AND retired_at IS NULL)
       OR (state = 'active' AND activated_at IS NOT NULL AND retired_at IS NULL)
       OR (state = 'retired' AND activated_at IS NOT NULL AND retired_at IS NOT NULL)),
    FOREIGN KEY(owner_key_id) REFERENCES authority_keys(key_id) ON DELETE RESTRICT,
    FOREIGN KEY(recovery_key_id) REFERENCES authority_keys(key_id) ON DELETE RESTRICT,
    FOREIGN KEY(predecessor_epoch) REFERENCES trust_epochs(epoch) ON DELETE RESTRICT,
    FOREIGN KEY(transition_receipt_id) REFERENCES authorization_receipts(receipt_id) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX trust_epochs_one_active
ON trust_epochs(state) WHERE state = 'active';
CREATE UNIQUE INDEX trust_epochs_one_staged
ON trust_epochs(state) WHERE state = 'staged';
CREATE UNIQUE INDEX trust_epochs_one_staged_successor
ON trust_epochs(predecessor_epoch) WHERE state = 'staged';

CREATE TRIGGER trust_epochs_key_roles_insert
BEFORE INSERT ON trust_epochs
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM authority_keys
        WHERE key_id = NEW.owner_key_id AND role = 'owner' AND permission_mask = 7
          AND valid_from_epoch <= NEW.epoch
          AND (NEW.epoch <> 1 OR (state = 'active' AND valid_from_epoch = 1))
    ) THEN RAISE(ABORT, 'trust epoch owner key role mismatch') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM authority_keys
        WHERE key_id = NEW.recovery_key_id AND role = 'recovery' AND permission_mask = 8
          AND valid_from_epoch <= NEW.epoch
          AND (NEW.epoch <> 1 OR (state = 'active' AND valid_from_epoch = 1))
    ) THEN RAISE(ABORT, 'trust epoch recovery key role mismatch') END;
END;

CREATE TRIGGER trust_epochs_key_roles_update
BEFORE UPDATE OF owner_key_id, recovery_key_id ON trust_epochs
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM authority_keys
        WHERE key_id = NEW.owner_key_id AND role = 'owner' AND permission_mask = 7
          AND valid_from_epoch <= NEW.epoch
          AND (NEW.epoch <> 1 OR (state = 'active' AND valid_from_epoch = 1))
    ) THEN RAISE(ABORT, 'trust epoch owner key role mismatch') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM authority_keys
        WHERE key_id = NEW.recovery_key_id AND role = 'recovery' AND permission_mask = 8
          AND valid_from_epoch <= NEW.epoch
          AND (NEW.epoch <> 1 OR (state = 'active' AND valid_from_epoch = 1))
    ) THEN RAISE(ABORT, 'trust epoch recovery key role mismatch') END;
END;

CREATE TABLE authority_meta (
    singleton INTEGER PRIMARY KEY
        CHECK(typeof(singleton) = 'integer' AND singleton = 1),
    bootstrap_state TEXT NOT NULL
        CHECK(typeof(bootstrap_state) = 'text'
          AND bootstrap_state IN ('pending_anchor','ready')),
    journal_id BLOB NOT NULL UNIQUE
        CHECK(typeof(journal_id) = 'blob' AND length(journal_id) = 16),
    realm_id BLOB NOT NULL UNIQUE
        CHECK(typeof(realm_id) = 'blob' AND length(realm_id) = 32),
    journal_location_sha256 BLOB NOT NULL
        CHECK(typeof(journal_location_sha256) = 'blob'
          AND length(journal_location_sha256) = 32),
    active_epoch INTEGER NOT NULL
        CHECK(typeof(active_epoch) = 'integer' AND active_epoch > 0),
    trust_bundle_sha256 BLOB NOT NULL
        CHECK(typeof(trust_bundle_sha256) = 'blob' AND length(trust_bundle_sha256) = 32),
    last_observed_at INTEGER NOT NULL
        CHECK(typeof(last_observed_at) = 'integer' AND last_observed_at >= 0),
    created_at INTEGER NOT NULL
        CHECK(typeof(created_at) = 'integer' AND created_at >= 0),
    updated_at INTEGER NOT NULL
        CHECK(typeof(updated_at) = 'integer' AND updated_at >= created_at),
    anchor_confirmed_at INTEGER
        CHECK(anchor_confirmed_at IS NULL OR
          (typeof(anchor_confirmed_at) = 'integer' AND anchor_confirmed_at >= created_at)),
    CHECK((bootstrap_state = 'pending_anchor' AND anchor_confirmed_at IS NULL)
       OR (bootstrap_state = 'ready' AND anchor_confirmed_at IS NOT NULL)),
    FOREIGN KEY(active_epoch) REFERENCES trust_epochs(epoch) ON DELETE RESTRICT
) STRICT;

CREATE TABLE registered_stores (
    store_id BLOB PRIMARY KEY
        CHECK(typeof(store_id) = 'blob' AND length(store_id) = 16),
    location_material BLOB NOT NULL
        CHECK(typeof(location_material) = 'blob'
          AND length(location_material) BETWEEN 1 AND 4096),
    location_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(location_sha256) = 'blob' AND length(location_sha256) = 32),
    config_generation INTEGER NOT NULL
        CHECK(typeof(config_generation) = 'integer' AND config_generation > 0),
    config_sha256 BLOB NOT NULL
        CHECK(typeof(config_sha256) = 'blob' AND length(config_sha256) = 32),
    state TEXT NOT NULL
        CHECK(typeof(state) = 'text'
          AND state IN ('active','blocked','removed','recovery_required')),
    enrolled_receipt_id BLOB NOT NULL UNIQUE
        CHECK(typeof(enrolled_receipt_id) = 'blob' AND length(enrolled_receipt_id) = 16),
    created_at INTEGER NOT NULL
        CHECK(typeof(created_at) = 'integer' AND created_at >= 0),
    updated_at INTEGER NOT NULL
        CHECK(typeof(updated_at) = 'integer' AND updated_at >= created_at),
    removed_at INTEGER
        CHECK(removed_at IS NULL OR
          (typeof(removed_at) = 'integer' AND removed_at >= created_at)),
    CHECK((state = 'removed' AND removed_at IS NOT NULL)
       OR (state != 'removed' AND removed_at IS NULL)),
    UNIQUE(store_id, location_sha256),
    UNIQUE(store_id, location_sha256, enrolled_receipt_id),
    FOREIGN KEY(enrolled_receipt_id) REFERENCES authorization_receipts(receipt_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE registered_accounts (
    account_id BLOB PRIMARY KEY
        CHECK(typeof(account_id) = 'blob' AND length(account_id) = 16),
    store_id BLOB NOT NULL
        CHECK(typeof(store_id) = 'blob' AND length(store_id) = 16),
    display_id_sha256 BLOB NOT NULL
        CHECK(typeof(display_id_sha256) = 'blob' AND length(display_id_sha256) = 32),
    account_generation INTEGER NOT NULL
        CHECK(typeof(account_generation) = 'integer' AND account_generation > 0),
    credential_id BLOB NOT NULL UNIQUE
        CHECK(typeof(credential_id) = 'blob' AND length(credential_id) = 16),
    binding_sha256 BLOB NOT NULL
        CHECK(typeof(binding_sha256) = 'blob' AND length(binding_sha256) = 32),
    state TEXT NOT NULL
        CHECK(typeof(state) = 'text' AND state IN ('proposed','active','blocked','removed')),
    authorized_receipt_id BLOB NOT NULL UNIQUE
        CHECK(typeof(authorized_receipt_id) = 'blob' AND length(authorized_receipt_id) = 16),
    active_transition_id BLOB UNIQUE
        CHECK(active_transition_id IS NULL OR
          (typeof(active_transition_id) = 'blob' AND length(active_transition_id) = 16)),
    created_at INTEGER NOT NULL
        CHECK(typeof(created_at) = 'integer' AND created_at >= 0),
    updated_at INTEGER NOT NULL
        CHECK(typeof(updated_at) = 'integer' AND updated_at >= created_at),
    removed_at INTEGER
        CHECK(removed_at IS NULL OR
          (typeof(removed_at) = 'integer' AND removed_at >= created_at)),
    CHECK((state = 'removed' AND removed_at IS NOT NULL AND active_transition_id IS NULL)
       OR (state != 'removed' AND removed_at IS NULL)),
    CHECK(active_transition_id IS NULL OR state IN ('proposed','blocked')),
    UNIQUE(account_id, store_id),
    UNIQUE(account_id, store_id, account_generation, credential_id, binding_sha256),
    FOREIGN KEY(store_id) REFERENCES registered_stores(store_id) ON DELETE RESTRICT,
    FOREIGN KEY(authorized_receipt_id) REFERENCES authorization_receipts(receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY(credential_id, account_id, store_id)
        REFERENCES registered_credentials(credential_id, account_id, store_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(active_transition_id) REFERENCES account_transitions(transition_id) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX registered_accounts_active_display_id
ON registered_accounts(store_id, display_id_sha256)
WHERE state IN ('proposed','active','blocked');
CREATE INDEX registered_accounts_store_state
ON registered_accounts(store_id, state);

CREATE TABLE authorization_challenges (
    challenge_id BLOB PRIMARY KEY
        CHECK(typeof(challenge_id) = 'blob' AND length(challenge_id) = 32),
    grant_id BLOB NOT NULL UNIQUE
        CHECK(typeof(grant_id) = 'blob' AND length(grant_id) = 16),
    action INTEGER NOT NULL
        CHECK(typeof(action) = 'integer'
          AND action IN (1,16,17,18,19,20,256,272,273,274,288,289,290,
                         512,513,528,529,530,544)),
    target_kind INTEGER NOT NULL
        CHECK(typeof(target_kind) = 'integer' AND target_kind IN (1,2,3,4,5,6,7,8,9)),
    target_id BLOB NOT NULL
        CHECK(typeof(target_id) = 'blob' AND length(target_id) BETWEEN 0 AND 256),
    store_id BLOB
        CHECK(store_id IS NULL OR (typeof(store_id) = 'blob' AND length(store_id) = 16)),
    account_id BLOB
        CHECK(account_id IS NULL OR (typeof(account_id) = 'blob' AND length(account_id) = 16)),
    context_sha256 BLOB NOT NULL
        CHECK(typeof(context_sha256) = 'blob' AND length(context_sha256) = 32),
    manifest BLOB NOT NULL
        CHECK(typeof(manifest) = 'blob' AND length(manifest) BETWEEN 1 AND 4194304),
    manifest_sha256 BLOB NOT NULL
        CHECK(typeof(manifest_sha256) = 'blob' AND length(manifest_sha256) = 32),
    signing_payload BLOB NOT NULL
        CHECK(typeof(signing_payload) = 'blob'
          AND length(signing_payload) BETWEEN 1 AND 4194304),
    signing_sha256 BLOB NOT NULL
        CHECK(typeof(signing_sha256) = 'blob' AND length(signing_sha256) = 32),
    key_id BLOB NOT NULL
        CHECK(typeof(key_id) = 'blob' AND length(key_id) = 32),
    trust_epoch INTEGER NOT NULL
        CHECK(typeof(trust_epoch) = 'integer' AND trust_epoch > 0),
    bundle_sha256 BLOB NOT NULL
        CHECK(typeof(bundle_sha256) = 'blob' AND length(bundle_sha256) = 32),
    binding_sha256 BLOB
        CHECK(binding_sha256 IS NULL OR
          (typeof(binding_sha256) = 'blob' AND length(binding_sha256) = 32)),
    policy_sha256 BLOB
        CHECK(policy_sha256 IS NULL OR
          (typeof(policy_sha256) = 'blob' AND length(policy_sha256) = 32)),
    nonce BLOB NOT NULL UNIQUE
        CHECK(typeof(nonce) = 'blob' AND length(nonce) = 32),
    issued_at INTEGER NOT NULL
        CHECK(typeof(issued_at) = 'integer' AND issued_at >= 0),
    expires_at INTEGER NOT NULL
        CHECK(typeof(expires_at) = 'integer' AND expires_at > issued_at
          AND expires_at - issued_at <= 900000),
    state TEXT NOT NULL
        CHECK(typeof(state) = 'text'
          AND state IN ('pending','authorized','expired','invalidated')),
    invalidated_at INTEGER
        CHECK(invalidated_at IS NULL OR
          (typeof(invalidated_at) = 'integer' AND invalidated_at >= issued_at)),
    created_event_sequence INTEGER
        CHECK(created_event_sequence IS NULL OR
          (typeof(created_event_sequence) = 'integer' AND created_event_sequence > 0)),
    CHECK(challenge_id = signing_sha256),
    CHECK((target_kind IN (1,2,3,4,5,9) AND length(target_id) = 16)
       OR (target_kind = 8 AND length(target_id) = 8)
       OR (target_kind IN (6,7) AND length(target_id) = 0)),
    CHECK((action IN (1,16,17,18,19,20) AND target_kind = 1)
       OR (action = 256 AND target_kind = 2)
       OR (action IN (272,273,274) AND target_kind = 3)
       OR (action IN (288,289) AND target_kind = 4)
       OR (action = 290 AND target_kind = 5)
       OR (action = 512 AND target_kind = 6)
       OR (action = 513 AND target_kind = 7)
       OR (action IN (528,529,530) AND target_kind = 8)
       OR (action = 544 AND target_kind = 9)),
    CHECK((action IN (1,16,17,18,19,20,544)
           AND store_id IS NOT NULL AND account_id IS NOT NULL
           AND binding_sha256 IS NOT NULL AND policy_sha256 IS NOT NULL)
       OR (action = 256 AND store_id IS NOT NULL AND account_id IS NULL
           AND binding_sha256 IS NULL AND policy_sha256 IS NULL)
       OR (action IN (272,273,274,288,289,290)
           AND store_id IS NOT NULL AND account_id IS NOT NULL
           AND binding_sha256 IS NOT NULL AND policy_sha256 IS NULL)
       OR (action IN (512,513,528,529,530)
           AND store_id IS NULL AND account_id IS NULL
           AND binding_sha256 IS NULL AND policy_sha256 IS NULL)),
    CHECK((state = 'invalidated' AND invalidated_at IS NOT NULL)
       OR (state != 'invalidated' AND invalidated_at IS NULL)),
    UNIQUE(challenge_id, grant_id),
    UNIQUE(challenge_id, nonce),
    UNIQUE(nonce, challenge_id),
    UNIQUE(grant_id, action, target_kind, target_id, manifest_sha256),
    UNIQUE(challenge_id, grant_id, key_id, trust_epoch, bundle_sha256,
           manifest_sha256, signing_sha256, expires_at),
    UNIQUE(challenge_id, grant_id, store_id, account_id, manifest_sha256,
           binding_sha256, policy_sha256, trust_epoch, bundle_sha256, key_id),
    FOREIGN KEY(key_id) REFERENCES authority_keys(key_id) ON DELETE RESTRICT,
    FOREIGN KEY(trust_epoch) REFERENCES trust_epochs(epoch) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX authorization_challenges_one_pending_context
ON authorization_challenges(context_sha256) WHERE state = 'pending';
CREATE INDEX authorization_challenges_context_created_sequence
ON authorization_challenges(context_sha256, created_event_sequence, challenge_id);
CREATE INDEX authorization_challenges_state_epoch_expiry
ON authorization_challenges(state, trust_epoch, expires_at);

CREATE TABLE challenge_effects (
    challenge_id BLOB NOT NULL
        CHECK(typeof(challenge_id) = 'blob' AND length(challenge_id) = 32),
    ordinal INTEGER NOT NULL
        CHECK(typeof(ordinal) = 'integer' AND ordinal BETWEEN 0 AND 7),
    effect_id BLOB NOT NULL UNIQUE
        CHECK(typeof(effect_id) = 'blob' AND length(effect_id) = 16),
    effect_kind INTEGER NOT NULL
        CHECK(typeof(effect_kind) = 'integer' AND effect_kind IN (1,2,3,4,5,6)),
    PRIMARY KEY(challenge_id, ordinal),
    UNIQUE(challenge_id, ordinal, effect_id, effect_kind),
    FOREIGN KEY(challenge_id) REFERENCES authorization_challenges(challenge_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE authorization_receipts (
    receipt_id BLOB PRIMARY KEY
        CHECK(typeof(receipt_id) = 'blob' AND length(receipt_id) = 16),
    challenge_id BLOB NOT NULL UNIQUE
        CHECK(typeof(challenge_id) = 'blob' AND length(challenge_id) = 32),
    grant_id BLOB NOT NULL UNIQUE
        CHECK(typeof(grant_id) = 'blob' AND length(grant_id) = 16),
    proof_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(proof_sha256) = 'blob' AND length(proof_sha256) = 32),
    key_id BLOB NOT NULL
        CHECK(typeof(key_id) = 'blob' AND length(key_id) = 32),
    signature BLOB NOT NULL
        CHECK(typeof(signature) = 'blob' AND length(signature) = 64),
    canonical_proof BLOB NOT NULL
        CHECK(typeof(canonical_proof) = 'blob'
          AND length(canonical_proof) BETWEEN 1 AND 4096),
    manifest_sha256 BLOB NOT NULL
        CHECK(typeof(manifest_sha256) = 'blob' AND length(manifest_sha256) = 32),
    signing_sha256 BLOB NOT NULL
        CHECK(typeof(signing_sha256) = 'blob' AND length(signing_sha256) = 32),
    trust_epoch INTEGER NOT NULL
        CHECK(typeof(trust_epoch) = 'integer' AND trust_epoch > 0),
    bundle_sha256 BLOB NOT NULL
        CHECK(typeof(bundle_sha256) = 'blob' AND length(bundle_sha256) = 32),
    receipt BLOB NOT NULL
        CHECK(typeof(receipt) = 'blob' AND length(receipt) BETWEEN 1 AND 16384),
    receipt_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(receipt_sha256) = 'blob' AND length(receipt_sha256) = 32),
    verified_at INTEGER NOT NULL
        CHECK(typeof(verified_at) = 'integer' AND verified_at >= 0),
    expires_at INTEGER NOT NULL
        CHECK(typeof(expires_at) = 'integer' AND expires_at >= verified_at),
    UNIQUE(receipt_id, challenge_id),
    UNIQUE(receipt_id, grant_id),
    UNIQUE(grant_id, receipt_id),
    FOREIGN KEY(challenge_id, grant_id, key_id, trust_epoch, bundle_sha256,
                manifest_sha256, signing_sha256, expires_at)
        REFERENCES authorization_challenges(
            challenge_id, grant_id, key_id, trust_epoch, bundle_sha256,
            manifest_sha256, signing_sha256, expires_at
        ) ON DELETE RESTRICT,
    FOREIGN KEY(key_id) REFERENCES authority_keys(key_id) ON DELETE RESTRICT,
    FOREIGN KEY(trust_epoch) REFERENCES trust_epochs(epoch) ON DELETE RESTRICT
) STRICT;

CREATE INDEX authorization_receipts_epoch_expiry
ON authorization_receipts(trust_epoch, expires_at);

CREATE TABLE nonce_uses (
    nonce BLOB PRIMARY KEY
        CHECK(typeof(nonce) = 'blob' AND length(nonce) = 32),
    challenge_id BLOB NOT NULL UNIQUE
        CHECK(typeof(challenge_id) = 'blob' AND length(challenge_id) = 32),
    receipt_id BLOB NOT NULL UNIQUE
        CHECK(typeof(receipt_id) = 'blob' AND length(receipt_id) = 16),
    consumed_at INTEGER NOT NULL
        CHECK(typeof(consumed_at) = 'integer' AND consumed_at >= 0),
    FOREIGN KEY(nonce, challenge_id)
        REFERENCES authorization_challenges(nonce, challenge_id) ON DELETE RESTRICT,
    FOREIGN KEY(receipt_id, challenge_id)
        REFERENCES authorization_receipts(receipt_id, challenge_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE grant_uses (
    grant_id BLOB PRIMARY KEY
        CHECK(typeof(grant_id) = 'blob' AND length(grant_id) = 16),
    receipt_id BLOB NOT NULL UNIQUE
        CHECK(typeof(receipt_id) = 'blob' AND length(receipt_id) = 16),
    action INTEGER NOT NULL
        CHECK(typeof(action) = 'integer'
          AND action IN (1,16,17,18,19,20,256,272,273,274,288,289,290,
                         512,513,528,529,530,544)),
    target_kind INTEGER NOT NULL
        CHECK(typeof(target_kind) = 'integer' AND target_kind IN (1,2,3,4,5,6,7,8,9)),
    target_id BLOB NOT NULL
        CHECK(typeof(target_id) = 'blob' AND length(target_id) BETWEEN 0 AND 256),
    manifest_sha256 BLOB NOT NULL
        CHECK(typeof(manifest_sha256) = 'blob' AND length(manifest_sha256) = 32),
    use_receipt BLOB NOT NULL
        CHECK(typeof(use_receipt) = 'blob' AND length(use_receipt) BETWEEN 1 AND 16384),
    use_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(use_sha256) = 'blob' AND length(use_sha256) = 32),
    used_at INTEGER NOT NULL
        CHECK(typeof(used_at) = 'integer' AND used_at >= 0),
    CHECK((target_kind IN (1,2,3,4,5,9) AND length(target_id) = 16)
       OR (target_kind = 8 AND length(target_id) = 8)
       OR (target_kind IN (6,7) AND length(target_id) = 0)),
    FOREIGN KEY(grant_id, receipt_id)
        REFERENCES authorization_receipts(grant_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY(grant_id, action, target_kind, target_id, manifest_sha256)
        REFERENCES authorization_challenges(
            grant_id, action, target_kind, target_id, manifest_sha256
        ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE account_transitions (
    transition_id BLOB PRIMARY KEY
        CHECK(typeof(transition_id) = 'blob' AND length(transition_id) = 16),
    grant_id BLOB NOT NULL UNIQUE
        CHECK(typeof(grant_id) = 'blob' AND length(grant_id) = 16),
    store_id BLOB NOT NULL
        CHECK(typeof(store_id) = 'blob' AND length(store_id) = 16),
    account_id BLOB NOT NULL
        CHECK(typeof(account_id) = 'blob' AND length(account_id) = 16),
    kind TEXT NOT NULL
        CHECK(typeof(kind) = 'text'
          AND kind IN ('account_create','account_update','account_remove',
                       'credential_set','credential_delete')),
    before_config_sha256 BLOB NOT NULL
        CHECK(typeof(before_config_sha256) = 'blob' AND length(before_config_sha256) = 32),
    after_config_sha256 BLOB NOT NULL
        CHECK(typeof(after_config_sha256) = 'blob' AND length(after_config_sha256) = 32),
    expected_generation INTEGER NOT NULL
        CHECK(typeof(expected_generation) = 'integer'
          AND expected_generation > 0 AND expected_generation < 9223372036854775807),
    next_generation INTEGER NOT NULL
        CHECK(typeof(next_generation) = 'integer'
          AND next_generation = expected_generation + 1),
    transition_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(transition_sha256) = 'blob' AND length(transition_sha256) = 32),
    state TEXT NOT NULL
        CHECK(typeof(state) = 'text'
          AND state IN ('prepared','config_committed','finalized','aborted','recovery_required')),
    prepared_at INTEGER NOT NULL
        CHECK(typeof(prepared_at) = 'integer' AND prepared_at >= 0),
    config_committed_at INTEGER
        CHECK(config_committed_at IS NULL OR
          (typeof(config_committed_at) = 'integer' AND config_committed_at >= prepared_at)),
    finalized_at INTEGER
        CHECK(finalized_at IS NULL OR
          (typeof(finalized_at) = 'integer' AND config_committed_at IS NOT NULL
           AND finalized_at >= config_committed_at)),
    resolved_at INTEGER
        CHECK(resolved_at IS NULL OR
          (typeof(resolved_at) = 'integer' AND resolved_at >= prepared_at)),
    CHECK((state = 'prepared' AND config_committed_at IS NULL
           AND finalized_at IS NULL AND resolved_at IS NULL)
       OR (state = 'config_committed' AND config_committed_at IS NOT NULL
           AND finalized_at IS NULL AND resolved_at IS NULL)
       OR (state = 'finalized' AND config_committed_at IS NOT NULL
           AND finalized_at IS NOT NULL AND resolved_at IS NULL)
       OR (state = 'aborted' AND config_committed_at IS NULL
           AND finalized_at IS NULL AND resolved_at IS NOT NULL)
       OR (state = 'recovery_required' AND finalized_at IS NULL
           AND resolved_at IS NOT NULL)),
    UNIQUE(transition_id, store_id),
    UNIQUE(transition_id, account_id, store_id),
    FOREIGN KEY(grant_id) REFERENCES grant_uses(grant_id) ON DELETE RESTRICT,
    FOREIGN KEY(store_id) REFERENCES registered_stores(store_id) ON DELETE RESTRICT,
    FOREIGN KEY(account_id, store_id)
        REFERENCES registered_accounts(account_id, store_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX account_transitions_store_state
ON account_transitions(store_id, state);
CREATE INDEX account_transitions_account_state
ON account_transitions(account_id, state);

CREATE TABLE registered_credentials (
    credential_id BLOB PRIMARY KEY
        CHECK(typeof(credential_id) = 'blob' AND length(credential_id) = 16),
    account_id BLOB NOT NULL
        CHECK(typeof(account_id) = 'blob' AND length(account_id) = 16),
    store_id BLOB NOT NULL
        CHECK(typeof(store_id) = 'blob' AND length(store_id) = 16),
    created_transition_id BLOB NOT NULL UNIQUE
        CHECK(typeof(created_transition_id) = 'blob'
          AND length(created_transition_id) = 16),
    created_at INTEGER NOT NULL
        CHECK(typeof(created_at) = 'integer' AND created_at >= 0),
    UNIQUE(credential_id, account_id, store_id),
    FOREIGN KEY(account_id, store_id)
        REFERENCES registered_accounts(account_id, store_id) ON DELETE RESTRICT,
    FOREIGN KEY(created_transition_id, account_id, store_id)
        REFERENCES account_transitions(transition_id, account_id, store_id)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE registered_store_versions (
    store_id BLOB NOT NULL
        CHECK(typeof(store_id) = 'blob' AND length(store_id) = 16),
    location_sha256 BLOB NOT NULL
        CHECK(typeof(location_sha256) = 'blob' AND length(location_sha256) = 32),
    config_generation INTEGER NOT NULL
        CHECK(typeof(config_generation) = 'integer' AND config_generation > 0),
    config_sha256 BLOB NOT NULL
        CHECK(typeof(config_sha256) = 'blob' AND length(config_sha256) = 32),
    enrolled_receipt_id BLOB UNIQUE
        CHECK(enrolled_receipt_id IS NULL OR
          (typeof(enrolled_receipt_id) = 'blob' AND length(enrolled_receipt_id) = 16)),
    committed_transition_id BLOB UNIQUE
        CHECK(committed_transition_id IS NULL OR
          (typeof(committed_transition_id) = 'blob'
           AND length(committed_transition_id) = 16)),
    created_at INTEGER NOT NULL
        CHECK(typeof(created_at) = 'integer' AND created_at >= 0),
    PRIMARY KEY(store_id, config_generation),
    CHECK((enrolled_receipt_id IS NOT NULL AND committed_transition_id IS NULL)
       OR (enrolled_receipt_id IS NULL AND committed_transition_id IS NOT NULL)),
    UNIQUE(store_id, config_generation, config_sha256),
    UNIQUE(store_id, location_sha256, config_generation, config_sha256),
    FOREIGN KEY(store_id, location_sha256)
        REFERENCES registered_stores(store_id, location_sha256) ON DELETE RESTRICT,
    FOREIGN KEY(store_id, location_sha256, enrolled_receipt_id)
        REFERENCES registered_stores(store_id, location_sha256, enrolled_receipt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(enrolled_receipt_id)
        REFERENCES authorization_receipts(receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY(committed_transition_id, store_id)
        REFERENCES account_transitions(transition_id, store_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE registered_account_versions (
    account_id BLOB NOT NULL
        CHECK(typeof(account_id) = 'blob' AND length(account_id) = 16),
    store_id BLOB NOT NULL
        CHECK(typeof(store_id) = 'blob' AND length(store_id) = 16),
    account_generation INTEGER NOT NULL
        CHECK(typeof(account_generation) = 'integer' AND account_generation > 0),
    credential_id BLOB NOT NULL
        CHECK(typeof(credential_id) = 'blob' AND length(credential_id) = 16),
    binding_sha256 BLOB NOT NULL
        CHECK(typeof(binding_sha256) = 'blob' AND length(binding_sha256) = 32),
    committed_transition_id BLOB NOT NULL UNIQUE
        CHECK(typeof(committed_transition_id) = 'blob'
          AND length(committed_transition_id) = 16),
    created_at INTEGER NOT NULL
        CHECK(typeof(created_at) = 'integer' AND created_at >= 0),
    PRIMARY KEY(account_id, account_generation),
    UNIQUE(account_id, store_id, account_generation, credential_id, binding_sha256),
    FOREIGN KEY(account_id, store_id)
        REFERENCES registered_accounts(account_id, store_id) ON DELETE RESTRICT,
    FOREIGN KEY(credential_id, account_id, store_id)
        REFERENCES registered_credentials(credential_id, account_id, store_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(committed_transition_id, account_id, store_id)
        REFERENCES account_transitions(transition_id, account_id, store_id)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE credential_cleanup (
    cleanup_id BLOB PRIMARY KEY
        CHECK(typeof(cleanup_id) = 'blob' AND length(cleanup_id) = 16),
    transition_id BLOB
        CHECK(transition_id IS NULL OR
          (typeof(transition_id) = 'blob' AND length(transition_id) = 16)),
    locator_kind TEXT NOT NULL
        CHECK(typeof(locator_kind) = 'text' AND locator_kind IN ('active_v2','legacy_v1')),
    locator_material BLOB NOT NULL
        CHECK(typeof(locator_material) = 'blob'
          AND length(locator_material) BETWEEN 1 AND 4096),
    locator_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(locator_sha256) = 'blob' AND length(locator_sha256) = 32),
    state TEXT NOT NULL
        CHECK(typeof(state) = 'text'
          AND state IN ('provisional','ready','claimed','deleted')),
    claim_grant_id BLOB UNIQUE
        CHECK(claim_grant_id IS NULL OR
          (typeof(claim_grant_id) = 'blob' AND length(claim_grant_id) = 16)),
    created_at INTEGER NOT NULL
        CHECK(typeof(created_at) = 'integer' AND created_at >= 0),
    deleted_at INTEGER
        CHECK(deleted_at IS NULL OR
          (typeof(deleted_at) = 'integer' AND deleted_at >= created_at)),
    CHECK((state IN ('provisional','ready') AND claim_grant_id IS NULL AND deleted_at IS NULL)
       OR (state = 'claimed' AND claim_grant_id IS NOT NULL AND deleted_at IS NULL)
       OR (state = 'deleted' AND claim_grant_id IS NOT NULL AND deleted_at IS NOT NULL)),
    FOREIGN KEY(transition_id) REFERENCES account_transitions(transition_id) ON DELETE RESTRICT,
    FOREIGN KEY(claim_grant_id) REFERENCES grant_uses(grant_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE remote_effects (
    effect_id BLOB PRIMARY KEY
        CHECK(typeof(effect_id) = 'blob' AND length(effect_id) = 16),
    challenge_id BLOB NOT NULL
        CHECK(typeof(challenge_id) = 'blob' AND length(challenge_id) = 32),
    grant_id BLOB NOT NULL UNIQUE
        CHECK(typeof(grant_id) = 'blob' AND length(grant_id) = 16),
    operation_id BLOB NOT NULL
        CHECK(typeof(operation_id) = 'blob' AND length(operation_id) = 16),
    ordinal INTEGER NOT NULL
        CHECK(typeof(ordinal) = 'integer' AND ordinal BETWEEN 0 AND 7),
    effect_kind INTEGER NOT NULL
        CHECK(typeof(effect_kind) = 'integer' AND effect_kind IN (1,2,3,4,5,6)),
    store_id BLOB NOT NULL
        CHECK(typeof(store_id) = 'blob' AND length(store_id) = 16),
    store_location_sha256 BLOB NOT NULL
        CHECK(typeof(store_location_sha256) = 'blob'
          AND length(store_location_sha256) = 32),
    account_id BLOB NOT NULL
        CHECK(typeof(account_id) = 'blob' AND length(account_id) = 16),
    config_generation INTEGER NOT NULL
        CHECK(typeof(config_generation) = 'integer' AND config_generation > 0),
    config_sha256 BLOB NOT NULL
        CHECK(typeof(config_sha256) = 'blob' AND length(config_sha256) = 32),
    account_generation INTEGER NOT NULL
        CHECK(typeof(account_generation) = 'integer' AND account_generation > 0),
    credential_id BLOB NOT NULL
        CHECK(typeof(credential_id) = 'blob' AND length(credential_id) = 16),
    manifest_sha256 BLOB NOT NULL
        CHECK(typeof(manifest_sha256) = 'blob' AND length(manifest_sha256) = 32),
    binding_sha256 BLOB NOT NULL
        CHECK(typeof(binding_sha256) = 'blob' AND length(binding_sha256) = 32),
    policy_sha256 BLOB NOT NULL
        CHECK(typeof(policy_sha256) = 'blob' AND length(policy_sha256) = 32),
    trust_epoch INTEGER NOT NULL
        CHECK(typeof(trust_epoch) = 'integer' AND trust_epoch > 0),
    bundle_sha256 BLOB NOT NULL
        CHECK(typeof(bundle_sha256) = 'blob' AND length(bundle_sha256) = 32),
    key_id BLOB NOT NULL
        CHECK(typeof(key_id) = 'blob' AND length(key_id) = 32),
    created_at INTEGER NOT NULL
        CHECK(typeof(created_at) = 'integer' AND created_at >= 0),
    UNIQUE(operation_id, ordinal),
    UNIQUE(challenge_id, ordinal),
    UNIQUE(effect_id, grant_id, operation_id, store_id, store_location_sha256,
           account_id, config_generation, config_sha256, account_generation,
           credential_id, manifest_sha256, binding_sha256, policy_sha256,
           trust_epoch, bundle_sha256, key_id),
    FOREIGN KEY(challenge_id, ordinal, effect_id, effect_kind)
        REFERENCES challenge_effects(challenge_id, ordinal, effect_id, effect_kind)
        ON DELETE RESTRICT,
    FOREIGN KEY(challenge_id, grant_id, store_id, account_id, manifest_sha256,
                binding_sha256, policy_sha256, trust_epoch, bundle_sha256, key_id)
        REFERENCES authorization_challenges(
            challenge_id, grant_id, store_id, account_id, manifest_sha256,
            binding_sha256, policy_sha256, trust_epoch, bundle_sha256, key_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY(grant_id) REFERENCES grant_uses(grant_id) ON DELETE RESTRICT,
    FOREIGN KEY(store_id, store_location_sha256, config_generation, config_sha256)
        REFERENCES registered_store_versions(
            store_id, location_sha256, config_generation, config_sha256
        ) ON DELETE RESTRICT,
    FOREIGN KEY(account_id, store_id, account_generation, credential_id, binding_sha256)
        REFERENCES registered_account_versions(
            account_id, store_id, account_generation, credential_id, binding_sha256
        ) ON DELETE RESTRICT,
    FOREIGN KEY(trust_epoch) REFERENCES trust_epochs(epoch) ON DELETE RESTRICT,
    FOREIGN KEY(key_id) REFERENCES authority_keys(key_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE effect_claims (
    claim_id BLOB PRIMARY KEY
        CHECK(typeof(claim_id) = 'blob' AND length(claim_id) = 16),
    effect_id BLOB NOT NULL UNIQUE
        CHECK(typeof(effect_id) = 'blob' AND length(effect_id) = 16),
    grant_id BLOB NOT NULL UNIQUE
        CHECK(typeof(grant_id) = 'blob' AND length(grant_id) = 16),
    operation_id BLOB NOT NULL
        CHECK(typeof(operation_id) = 'blob' AND length(operation_id) = 16),
    store_id BLOB NOT NULL
        CHECK(typeof(store_id) = 'blob' AND length(store_id) = 16),
    store_location_sha256 BLOB NOT NULL
        CHECK(typeof(store_location_sha256) = 'blob'
          AND length(store_location_sha256) = 32),
    account_id BLOB NOT NULL
        CHECK(typeof(account_id) = 'blob' AND length(account_id) = 16),
    config_generation INTEGER NOT NULL
        CHECK(typeof(config_generation) = 'integer' AND config_generation > 0),
    config_sha256 BLOB NOT NULL
        CHECK(typeof(config_sha256) = 'blob' AND length(config_sha256) = 32),
    account_generation INTEGER NOT NULL
        CHECK(typeof(account_generation) = 'integer' AND account_generation > 0),
    credential_id BLOB NOT NULL
        CHECK(typeof(credential_id) = 'blob' AND length(credential_id) = 16),
    manifest_sha256 BLOB NOT NULL
        CHECK(typeof(manifest_sha256) = 'blob' AND length(manifest_sha256) = 32),
    binding_sha256 BLOB NOT NULL
        CHECK(typeof(binding_sha256) = 'blob' AND length(binding_sha256) = 32),
    policy_sha256 BLOB NOT NULL
        CHECK(typeof(policy_sha256) = 'blob' AND length(policy_sha256) = 32),
    trust_epoch INTEGER NOT NULL
        CHECK(typeof(trust_epoch) = 'integer' AND trust_epoch > 0),
    bundle_sha256 BLOB NOT NULL
        CHECK(typeof(bundle_sha256) = 'blob' AND length(bundle_sha256) = 32),
    key_id BLOB NOT NULL
        CHECK(typeof(key_id) = 'blob' AND length(key_id) = 32),
    claim_receipt BLOB NOT NULL
        CHECK(typeof(claim_receipt) = 'blob'
          AND length(claim_receipt) BETWEEN 1 AND 65536),
    claim_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(claim_sha256) = 'blob' AND length(claim_sha256) = 32),
    claimed_at INTEGER NOT NULL
        CHECK(typeof(claimed_at) = 'integer' AND claimed_at >= 0),
    invoke_before INTEGER NOT NULL
        CHECK(typeof(invoke_before) = 'integer' AND invoke_before >= claimed_at),
    UNIQUE(effect_id, claim_id),
    FOREIGN KEY(effect_id, grant_id, operation_id, store_id,
                store_location_sha256, account_id, config_generation,
                config_sha256, account_generation, credential_id,
                manifest_sha256, binding_sha256, policy_sha256, trust_epoch,
                bundle_sha256, key_id)
        REFERENCES remote_effects(
            effect_id, grant_id, operation_id, store_id,
            store_location_sha256, account_id, config_generation,
            config_sha256, account_generation, credential_id,
            manifest_sha256, binding_sha256, policy_sha256, trust_epoch,
            bundle_sha256, key_id
        ) ON DELETE RESTRICT
) STRICT;

CREATE INDEX effect_claims_invoke_before
ON effect_claims(invoke_before);

CREATE TABLE effect_invocations (
    invocation_id BLOB PRIMARY KEY
        CHECK(typeof(invocation_id) = 'blob' AND length(invocation_id) = 16),
    effect_id BLOB NOT NULL UNIQUE
        CHECK(typeof(effect_id) = 'blob' AND length(effect_id) = 16),
    claim_id BLOB NOT NULL UNIQUE
        CHECK(typeof(claim_id) = 'blob' AND length(claim_id) = 16),
    session_id BLOB NOT NULL
        CHECK(typeof(session_id) = 'blob' AND length(session_id) = 16),
    start_receipt BLOB NOT NULL
        CHECK(typeof(start_receipt) = 'blob'
          AND length(start_receipt) BETWEEN 1 AND 65536),
    start_sha256 BLOB NOT NULL UNIQUE
        CHECK(typeof(start_sha256) = 'blob' AND length(start_sha256) = 32),
    started_at INTEGER NOT NULL
        CHECK(typeof(started_at) = 'integer' AND started_at >= 0),
    UNIQUE(effect_id, claim_id, invocation_id),
    FOREIGN KEY(effect_id, claim_id)
        REFERENCES effect_claims(effect_id, claim_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE effect_observations (
    observation_id BLOB PRIMARY KEY
        CHECK(typeof(observation_id) = 'blob' AND length(observation_id) = 32),
    effect_id BLOB NOT NULL UNIQUE
        CHECK(typeof(effect_id) = 'blob' AND length(effect_id) = 16),
    claim_id BLOB NOT NULL UNIQUE
        CHECK(typeof(claim_id) = 'blob' AND length(claim_id) = 16),
    invocation_id BLOB NOT NULL UNIQUE
        CHECK(typeof(invocation_id) = 'blob' AND length(invocation_id) = 16),
    certainty INTEGER NOT NULL
        CHECK(typeof(certainty) = 'integer' AND certainty IN (1,2,3)),
    result BLOB NOT NULL
        CHECK(typeof(result) = 'blob' AND length(result) BETWEEN 1 AND 16777216),
    result_sha256 BLOB NOT NULL
        CHECK(typeof(result_sha256) = 'blob' AND length(result_sha256) = 32),
    source INTEGER NOT NULL
        CHECK(typeof(source) = 'integer' AND source IN (1,2,3)),
    observation BLOB NOT NULL
        CHECK(typeof(observation) = 'blob' AND length(observation) BETWEEN 1 AND 4096),
    observed_at INTEGER NOT NULL
        CHECK(typeof(observed_at) = 'integer' AND observed_at >= 0),
    CHECK((source = 2 AND certainty = 2)
       OR (source = 3 AND certainty = 3)
       OR source = 1),
    FOREIGN KEY(effect_id, claim_id, invocation_id)
        REFERENCES effect_invocations(effect_id, claim_id, invocation_id)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE authority_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT
        CHECK(typeof(sequence) = 'integer' AND sequence > 0),
    entity_kind INTEGER NOT NULL
        CHECK(typeof(entity_kind) = 'integer' AND entity_kind BETWEEN 1 AND 13),
    entity_id BLOB NOT NULL
        CHECK(typeof(entity_id) = 'blob' AND length(entity_id) BETWEEN 1 AND 32),
    event_code INTEGER NOT NULL
        CHECK(typeof(event_code) = 'integer' AND event_code BETWEEN 1 AND 26),
    source INTEGER NOT NULL
        CHECK(typeof(source) = 'integer' AND source BETWEEN 1 AND 6),
    occurred_at INTEGER NOT NULL
        CHECK(typeof(occurred_at) = 'integer' AND occurred_at >= 0),
    detail BLOB NOT NULL
        CHECK(typeof(detail) = 'blob' AND length(detail) BETWEEN 1 AND 65536),
    detail_sha256 BLOB NOT NULL
        CHECK(typeof(detail_sha256) = 'blob' AND length(detail_sha256) = 32)
) STRICT;

CREATE INDEX authority_events_entity_sequence
ON authority_events(entity_kind, entity_id, sequence);


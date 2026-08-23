// Encryption configuration specification.
//
// Models the encryption key configuration invariants:
// - An encryption key is used for encrypting new data
// - Decryption keys are used for decrypting data (supports key rotation)
// - The encryption key must always be present in the decryption keys list

module encryption {
  type EncryptionKey = {
    id: str,
  }

  type Config = {
    encryptionKey: EncryptionKey,
    decryptionKeys: Set[EncryptionKey],
  }

  var config: Config

  action init = all {
    config' = {
      encryptionKey: { id: "default" },
      decryptionKeys: Set({ id: "default" }),
    },
  }

  // The encryption key must be present in decryption keys.
  val encryptionKeyInDecryptionKeys: bool =
    config.decryptionKeys.contains(config.encryptionKey)

  // At least one decryption key must exist.
  val hasDecryptionKeys: bool =
    config.decryptionKeys.size() > 0

  // Key ids within decryption keys are unique.
  def keyIdsUnique(keySet: Set[EncryptionKey]): bool =
    keySet.forall(k1 =>
      keySet.forall(k2 =>
        k1.id == k2.id implies k1 == k2))

  val decryptionKeyIdsUnique: bool =
    keyIdsUnique(config.decryptionKeys)

  // Set the encryption key (also adds to decryption keys if missing).
  action setEncryptionKey(key: EncryptionKey): bool = all {
    config' = {
      encryptionKey: key,
      decryptionKeys: config.decryptionKeys.union(Set(key)),
    },
  }

  // Add a decryption key for key rotation.
  action addDecryptionKey(key: EncryptionKey): bool = all {
    not(config.decryptionKeys.exists(k => k.id == key.id)),
    config' = {
      ...config,
      decryptionKeys: config.decryptionKeys.union(Set(key)),
    },
  }

  // Remove a decryption key (cannot remove the encryption key).
  action removeDecryptionKey(key: EncryptionKey): bool = all {
    key.id != config.encryptionKey.id,
    config.decryptionKeys.contains(key),
    config' = {
      ...config,
      decryptionKeys: config.decryptionKeys.exclude(Set(key)),
    },
  }

  // Rotate to a new encryption key.
  action rotateKey(newKey: EncryptionKey): bool = all {
    not(config.decryptionKeys.exists(k => k.id == newKey.id)),
    config' = {
      encryptionKey: newKey,
      decryptionKeys: config.decryptionKeys.union(Set(newKey)),
    },
  }

  action step: bool = all {
    config' = config,
  }

  // Tests

  run initHasEncryptionKeyInDecryptionKeys = {
    init.then(all {
      assert(encryptionKeyInDecryptionKeys),
      config' = config,
    })
  }

  run setEncryptionKeyAddsToDecryptionKeys = {
    init
      .then(setEncryptionKey({ id: "new-key" }))
      .then(all {
        assert(config.encryptionKey.id == "new-key"),
        assert(config.decryptionKeys.contains({ id: "new-key" })),
        assert(encryptionKeyInDecryptionKeys),
        config' = config,
      })
  }

  run cannotRemoveEncryptionKey = {
    init
      .then(removeDecryptionKey({ id: "default" }))
      .fail()
  }

  run keyRotationPreservesOldKeys = {
    init
      .then(rotateKey({ id: "v2" }))
      .then(all {
        assert(config.encryptionKey.id == "v2"),
        assert(config.decryptionKeys.contains({ id: "default" })),
        assert(config.decryptionKeys.contains({ id: "v2" })),
        assert(encryptionKeyInDecryptionKeys),
        config' = config,
      })
  }

  run canAddDecryptionKeyForRotation = {
    init
      .then(addDecryptionKey({ id: "old-key" }))
      .then(all {
        assert(config.decryptionKeys.size() == 2),
        assert(config.decryptionKeys.contains({ id: "old-key" })),
        config' = config,
      })
  }

  run cannotAddDuplicateDecryptionKeyId = {
    init
      .then(addDecryptionKey({ id: "default" }))
      .fail()
  }

  run canRemoveOldDecryptionKey = {
    init
      .then(addDecryptionKey({ id: "old-key" }))
      .then(removeDecryptionKey({ id: "old-key" }))
      .then(all {
        assert(config.decryptionKeys.size() == 1),
        assert(not(config.decryptionKeys.contains({ id: "old-key" }))),
        config' = config,
      })
  }
}

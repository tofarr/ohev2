// MCP server config resource specification.
//
// Models persisted MCP server configurations and the per-role grant table that
// controls read/update/delete access. Secret-bearing MCP fields are represented
// as encrypted booleans: when a config carries env/header/auth secrets, the
// implementation must persist ciphertext, not plaintext.

module mcp_server_config {
  type MCPServerConfig = {
    id: str,
    userId: str,
    displayName: str,
    transport: str,
    url: str,
    command: str,
    hasEnv: bool,
    envEncrypted: bool,
    hasHeaders: bool,
    headersEncrypted: bool,
    hasAuth: bool,
    authEncrypted: bool,
    enabled: bool,
    createdAt: int,
    updatedAt: int,
  }

  type RoleMCPServerConfigPermission = {
    id: str,
    roleId: str,
    mcpServerConfigId: str,
    readEnabled: bool,
    updateEnabled: bool,
    deleteEnabled: bool,
  }

  var configs: Set[MCPServerConfig]
  var grants: Set[RoleMCPServerConfigPermission]

  action init = all {
    configs' = Set(),
    grants' = Set(),
  }

  def configIdUnique(c1: MCPServerConfig, c2: MCPServerConfig): bool =
    c1.id == c2.id implies c1 == c2

  def grantIdUnique(g1: RoleMCPServerConfigPermission,
                    g2: RoleMCPServerConfigPermission): bool =
    g1.id == g2.id implies g1 == g2

  def grantPairUnique(g1: RoleMCPServerConfigPermission,
                      g2: RoleMCPServerConfigPermission): bool =
    (g1.roleId == g2.roleId and g1.mcpServerConfigId == g2.mcpServerConfigId)
      implies g1 == g2

  def secretsEncrypted(c: MCPServerConfig): bool =
    (not(c.hasEnv) or c.envEncrypted)
      and (not(c.hasHeaders) or c.headersEncrypted)
      and (not(c.hasAuth) or c.authEncrypted)

  action createConfig(c: MCPServerConfig): bool = all {
    not(configs.exists(existing => existing.id == c.id)),
    c.displayName != "",
    secretsEncrypted(c),
    configs' = configs.union(Set(c)),
    grants' = grants,
    true
  }

  action grantAccess(g: RoleMCPServerConfigPermission): bool = all {
    configs.exists(c => c.id == g.mcpServerConfigId),
    not(grants.exists(existing => existing.id == g.id)),
    not(grants.exists(existing =>
      existing.roleId == g.roleId
        and existing.mcpServerConfigId == g.mcpServerConfigId)),
    configs' = configs,
    grants' = grants.union(Set(g)),
    true
  }

  action updateGrant(id: str, readEnabled: bool,
                     updateEnabled: bool, deleteEnabled: bool): bool = all {
    grants.exists(g => g.id == id),
    configs' = configs,
    grants' = grants.map(g =>
      if (g.id == id)
        { id: g.id, roleId: g.roleId, mcpServerConfigId: g.mcpServerConfigId,
          readEnabled: readEnabled, updateEnabled: updateEnabled,
          deleteEnabled: deleteEnabled }
      else
        g),
    true
  }

  action deleteConfig(id: str): bool = all {
    configs.exists(c => c.id == id),
    configs' = configs.filter(c => c.id != id),
    grants' = grants.filter(g => g.mcpServerConfigId != id),
    true
  }

  val configIdsUnique: bool =
    configs.forall(c1 => configs.forall(c2 => configIdUnique(c1, c2)))

  val displayNamesNonEmpty: bool =
    configs.forall(c => c.displayName != "")

  val configSecretsEncrypted: bool =
    configs.forall(c => secretsEncrypted(c))

  val grantIdsUnique: bool =
    grants.forall(g1 => grants.forall(g2 => grantIdUnique(g1, g2)))

  val grantPairsUnique: bool =
    grants.forall(g1 => grants.forall(g2 => grantPairUnique(g1, g2)))

  val grantsReferenceConfig: bool =
    grants.forall(g => configs.exists(c => c.id == g.mcpServerConfigId))

  pure def sampleConfig(id: str): MCPServerConfig =
    { id: id, userId: "u1", displayName: "filesystem", transport: "stdio",
      url: "", command: "npx", hasEnv: true, envEncrypted: true,
      hasHeaders: true, headersEncrypted: true, hasAuth: true,
      authEncrypted: true, enabled: true, createdAt: 0, updatedAt: 0 }

  run canCreateEncryptedConfig = {
    init.then(createConfig(sampleConfig("m1")))
      .then(all {
        assert(configs.exists(c => c.id == "m1")),
        grants' = grants,
        configs' = configs,
      })
  }

  run cannotCreatePlaintextSecretConfig = {
    init.then(createConfig({ id: "m1", userId: "u1", displayName: "bad",
      transport: "stdio", url: "", command: "npx", hasEnv: true,
      envEncrypted: false, hasHeaders: false, headersEncrypted: false,
      hasAuth: false, authEncrypted: false, enabled: true,
      createdAt: 0, updatedAt: 0 })).fail()
  }

  run canGrantExistingConfig = {
    init.then(createConfig(sampleConfig("m1")))
      .then(grantAccess({ id: "g1", roleId: "r1", mcpServerConfigId: "m1",
        readEnabled: true, updateEnabled: false, deleteEnabled: false }))
      .then(all {
        assert(grants.exists(g => g.id == "g1" and g.readEnabled)),
        configs' = configs,
        grants' = grants,
      })
  }

  run cannotGrantMissingConfig = {
    init.then(grantAccess({ id: "g1", roleId: "r1", mcpServerConfigId: "missing",
      readEnabled: true, updateEnabled: false, deleteEnabled: false })).fail()
  }

  run deleteConfigCascadesGrants = {
    init.then(createConfig(sampleConfig("m1")))
      .then(grantAccess({ id: "g1", roleId: "r1", mcpServerConfigId: "m1",
        readEnabled: true, updateEnabled: false, deleteEnabled: false }))
      .then(deleteConfig("m1"))
      .then(all {
        assert(not(grants.exists(g => g.mcpServerConfigId == "m1"))),
        configs' = configs,
        grants' = grants,
      })
  }
}

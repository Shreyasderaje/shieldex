// Parses package.json + package-lock.json (npm lockfile versions 1, 2 and 3)
// into *package instances*: one entry per installed copy, identified by
// (name, resolved version, installation path). Two installed versions of the
// same package are never merged or overwritten — each gets its own install
// path and its own row in the report.
//
// Direct vs transitive classification is evidence-based:
//  - "direct"  : the instance is the one resolved from the root for a name
//                listed in package.json (dependencies / devDependencies /
//                optionalDependencies / peerDependencies).
//  - "dev-only": reachable from devDependencies but NOT reachable from any
//                production dependency (traversed through the lockfile's own
//                dependency edges).
// SECURITY: this module only JSON-parses text. It never executes, installs,
// or evaluates anything from the uploaded files; script contents are ignored
// (only the lockfile's boolean hasInstallScript flag is read as data).

const NODE_MODULES = 'node_modules/';

export function nameFromInstallPath(key) {
  const idx = key.lastIndexOf(NODE_MODULES);
  if (idx === -1) return null;
  return key.slice(idx + NODE_MODULES.length) || null;
}

export function parseJsonText(label, text) {
  if (text === undefined || text === null || String(text).trim() === '') {
    return { ok: false, error: `${label} is empty` };
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch (err) {
    return { ok: false, error: `${label} is not valid JSON: ${err.message}` };
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return { ok: false, error: `${label} must be a JSON object` };
  }
  return { ok: true, value };
}

export function detectLockfileVersion(lock) {
  if (typeof lock.lockfileVersion === 'number' && Number.isFinite(lock.lockfileVersion)) {
    return lock.lockfileVersion;
  }
  if (lock.packages) return 2; // packages key without a version field (npm 7)
  if (lock.dependencies) return 1;
  return null;
}

/**
 * @param {object|null} pkg parsed package.json (may be null when only a
 *                        lockfile was uploaded)
 * @param {object} lock  parsed package-lock.json
 */
export function buildDependencyGraph(pkg, lock) {
  const warnings = [];
  lock = lock || {};
  const hasLockStructure = Boolean(lock.packages || lock.dependencies);
  const lockVersion = hasLockStructure ? detectLockfileVersion(lock) : null;
  if (hasLockStructure && (lockVersion === null || lockVersion > 3)) {
    return { ok: false, error: 'Unrecognized package-lock.json structure (no `packages` or `dependencies` map)' };
  }

  const instances = [];

  if (lock.packages && typeof lock.packages === 'object') {
    // Lockfile v2 / v3 format.
    for (const [key, entry] of Object.entries(lock.packages)) {
      if (key === '' || !entry || typeof entry !== 'object') continue;
      if (typeof entry.version !== 'string' || !entry.version) {
        if (entry.link) {
          warnings.push(`Skipped link dependency at ${key} (workspace/file link, no installed copy to scan)`);
        } else {
          warnings.push(`Skipped lockfile entry at ${key} (no resolved version)`);
        }
        continue;
      }
      instances.push({
        installPath: key,
        name: nameFromInstallPath(key),
        version: entry.version,
        rawDeps: typeof entry.dependencies === 'object' && entry.dependencies ? entry.dependencies : {},
        optionalFlag: entry.optional === true,
        devFlag: entry.dev === true,
        hasInstallScript:
          entry.hasInstallScript === true ||
          Boolean(
            entry.scripts &&
              (entry.scripts.preinstall || entry.scripts.install || entry.scripts.postinstall),
          ),
      });
    }
  } else if (lock.dependencies && typeof lock.dependencies === 'object') {
    // Lockfile v1 format: nested dependency tree, walked recursively so that
    // nested installs under e.g. node_modules/foo/node_modules/bar keep their
    // own entries.
    const walk = (depsMap, parentPath) => {
      if (!depsMap || typeof depsMap !== 'object') return;
      for (const [name, entry] of Object.entries(depsMap)) {
        if (!entry || typeof entry !== 'object') continue;
        const installPath = (parentPath ? `${parentPath}/` : '') + `${NODE_MODULES}${name}`;
        if (typeof entry.version === 'string' && entry.version) {
          instances.push({
            installPath,
            name,
            version: entry.version,
            rawDeps: typeof entry.requires === 'object' && entry.requires ? entry.requires : {},
            optionalFlag: entry.optional === true,
            devFlag: entry.dev === true,
            hasInstallScript: entry.hasInstallScript === true,
          });
        } else {
          warnings.push(`Skipped lockfile entry at ${installPath} (no resolved version)`);
        }
        walk(entry.dependencies, installPath);
      }
    };
    walk(lock.dependencies, '');
  }

  if (!instances.length) {
    // No lockfile data (or a lockfile with no installed packages): fall back
    // to declared dependencies from package.json with unknown versions. These
    // cannot be vulnerability-scanned (OSV needs exact resolved versions) and
    // will be reported as such.
    if (pkg) {
      const groups = [
        ['dependencies', 'prod'],
        ['devDependencies', 'dev'],
        ['optionalDependencies', 'prod'],
        ['peerDependencies', 'peer'],
      ];
      for (const [field, kind] of groups) {
        for (const name of Object.keys(pkg[field] || {})) {
          instances.push({
            installPath: `unresolved:${field}:${name}`,
            name,
            version: null,
            declaredRange: pkg[field][name],
            rawDeps: {},
            optionalFlag: field === 'optionalDependencies',
            devFlag: kind === 'dev',
            hasInstallScript: false,
            declaredOnly: true,
          });
        }
      }
      if (instances.length) {
        warnings.push(
          'No package-lock.json (or it contains no installed packages): exact installed versions are unknown, so the vulnerability scan was skipped. Upload the lockfile for real vulnerability detection.',
        );
      }
    }
  }

  const byKey = new Map(instances.map((inst) => [inst.installPath, inst]));

  // Resolve every declared dependency edge to the instance that satisfies it,
  // mirroring Node's resolution: nearest node_modules walking up the tree.
  const resolveDep = (fromPath, name) => {
    let dir = fromPath;
    for (;;) {
      const candidate = dir === '' ? `${NODE_MODULES}${name}` : `${dir}/${NODE_MODULES}${name}`;
      if (byKey.has(candidate)) return candidate;
      if (dir === '') return null;
      const idx = dir.lastIndexOf(`/${NODE_MODULES}`);
      if (idx === -1) {
        dir = '';
      } else {
        dir = dir.slice(0, idx);
      }
    }
  };

  for (const inst of instances) {
    if (inst.declaredOnly) {
      inst.edges = [];
      continue;
    }
    inst.edges = Object.entries(inst.rawDeps)
      .map(([name, range]) => ({ name, range, resolvedPath: resolveDep(inst.installPath, name) }))
      .filter((edge) => {
        if (edge.resolvedPath) return true;
        // Bundled / optional / omitted deps may legitimately be absent.
        return false;
      });
    delete inst.rawDeps;
  }

  // ---- Direct / transitive / dev classification (evidence-based) ----
  const directProd = new Set([
    ...Object.keys(pkg?.dependencies || {}),
    ...Object.keys(pkg?.optionalDependencies || {}),
  ]);
  const directDev = new Set([
    ...Object.keys(pkg?.devDependencies || {}),
    ...Object.keys(pkg?.peerDependencies || {}),
  ]);

  // Fallbacks when package.json was not provided: use the lockfile's own
  // root evidence (v2/v3 root entry, or v1's dev flags / lockfileVersion).
  if (!pkg && lock.packages && lock.packages['']) {
    const root = lock.packages[''];
    for (const name of Object.keys(root.dependencies || {})) directProd.add(name);
    for (const name of Object.keys(root.devDependencies || {})) directDev.add(name);
  }

  const rootProdResolved = new Map();
  for (const name of directProd) rootProdResolved.set(name, resolveDep('', name));
  const rootDevResolved = new Map();
  for (const name of directDev) rootDevResolved.set(name, resolveDep('', name));

  const bfs = (roots) => {
    const seen = new Set();
    const queue = [];
    for (const p of roots) if (p && !seen.has(p)) { seen.add(p); queue.push(p); }
    while (queue.length) {
      const path = queue.shift();
      const inst = byKey.get(path);
      if (!inst) continue;
      for (const edge of inst.edges) {
        if (edge.resolvedPath && !seen.has(edge.resolvedPath)) {
          seen.add(edge.resolvedPath);
          queue.push(edge.resolvedPath);
        }
      }
    }
    return seen;
  };

  const prodReachable = bfs(rootProdResolved.values());
  const devReachable = bfs(rootDevResolved.values());

  for (const inst of instances) {
    if (inst.declaredOnly) {
      inst.isDirect = true;
      inst.devOnly = inst.devFlag;
      inst.evidence = {
        isDirect: 'declared in package.json (no lockfile entry)',
        devOnly: inst.devFlag ? 'package.json#devDependencies (no lockfile to confirm reachability)' : 'assumed production (no lockfile)',
      };
      continue;
    }
    const isTopLevel = inst.installPath === `${NODE_MODULES}${inst.name}`;
    const directProdHit = directProd.has(inst.name) && rootProdResolved.get(inst.name) === inst.installPath;
    const directDevHit = directDev.has(inst.name) && rootDevResolved.get(inst.name) === inst.installPath;
    inst.isDirect = Boolean(directProdHit || directDevHit);

    let devEvidence;
    if (prodReachable.has(inst.installPath)) {
      inst.devOnly = false;
      devEvidence = 'reachable from production dependency edges in the lockfile';
    } else if (devReachable.has(inst.installPath)) {
      inst.devOnly = true;
      devEvidence = 'reachable only via devDependency edges in the lockfile';
    } else {
      inst.devOnly = inst.devFlag;
      devEvidence = inst.devFlag
        ? 'lockfile dev flag (not reachable from declared dependencies)'
        : 'not reachable from declared dependencies (possibly optional/omitted edge)';
    }

    const directEvidence = directProdHit
      ? 'resolved from package.json#dependencies'
      : directDevHit
        ? 'resolved from package.json#devDependencies'
        : isTopLevel
          ? 'top-level lockfile entry not matching any declared dependency'
          : 'nested lockfile entry (transitive)';
    inst.evidence = { isDirect: directEvidence, devOnly: devEvidence };

    if (!inst.isDirect && isTopLevel && !directProd.has(inst.name) && !directDev.has(inst.name) && pkg) {
      warnings.push(
        `${inst.name} is installed at the top level but is not declared in package.json (may be a bundled or omitted dependency)`,
      );
    }
  }

  // Duplicate-version summary: same name installed at multiple versions.
  const byName = new Map();
  for (const inst of instances) {
    if (!byName.has(inst.name)) byName.set(inst.name, new Set());
    byName.get(inst.name).add(inst.version);
  }
  const duplicates = [];
  for (const [name, versions] of byName) {
    if (versions.size > 1) duplicates.push({ name, versions: [...versions] });
  }

  const projectName = pkg?.name || lock.name || 'unknown';
  const projectVersion = pkg?.version || lock.version || 'unknown';

  return {
    ok: true,
    lockfileVersion: lockVersion,
    projectName,
    projectVersion,
    instances,
    duplicates,
    warnings,
    stats: {
      totalInstances: instances.length,
      uniquePackages: new Set(instances.filter((i) => !i.declaredOnly).map((i) => `${i.name}@${i.version}`)).size,
      uniqueNames: byName.size,
      duplicateVersionPackages: duplicates.length,
    },
  };
}

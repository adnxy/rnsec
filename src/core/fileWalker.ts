import fg from 'fast-glob';
import { resolve, basename } from 'path';
import { filterGitTracked, filterGitIgnored, isGitRepository } from '../utils/gitUtils.js';

export interface FileGroup {
  jsFiles: string[];
  jsonFiles: string[];
  xmlFiles: string[];
  plistFiles: string[];
  /** `.env*` files that are tracked by git (ignored local env files are never reported) */
  envFiles: string[];
  /** `build.gradle`, `build.gradle.kts` and git-tracked `gradle.properties` */
  gradleFiles: string[];
  /** Git-tracked `.npmrc` / `.yarnrc.yml` */
  registryFiles: string[];
  /** Git-tracked signing keys and service-account files (never parsed for code, only reported) */
  credentialFiles: string[];
  /** `.java`, `.kt`, `.swift`, `.m`, `.mm` sources (build output, vendored code and test targets excluded) */
  nativeFiles: string[];
  /** iOS `.entitlements` files (XML plists) */
  entitlementFiles: string[];
  /** Firebase `*.rules`, `*.rules.json` (incl. `database.rules.json`) and `firebase.json` */
  firebaseRuleFiles: string[];
  /** `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` */
  lockfiles: string[];
  /** Git-tracked `sentry.properties`, `keystore.properties`, `signing.properties` and EAS `credentials.json` */
  credentialPropertyFiles: string[];
  /** Android `src/<set>/res/xml/*.xml` (FileProvider paths etc.; `network_security_config.xml` stays in `xmlFiles`) */
  resXmlFiles: string[];
}

export interface WalkOptions {
  /** Drop files git ignores (default true). Tracked files are always kept. */
  respectGitignore?: boolean;
  /** Called with the number of candidate files that could not be checked because the root is not in a git repository. */
  onUnverifiedFiles?: (count: number) => void;
}

/** Basenames (and name patterns) that are collected besides JS/TS sources. */
const COLLECTED_FILE_NAMES = new Set([
  'app.json',
  'app.config.json',
  'eas.json',
  'package.json',
  'AndroidManifest.xml',
  'network_security_config.xml',
  'Info.plist',
  'build.gradle',
  'build.gradle.kts',
  'gradle.properties',
  '.npmrc',
  '.yarnrc.yml',
  'firebase.json',
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'sentry.properties',
  'keystore.properties',
  'signing.properties',
  'credentials.json',
]);
const COLLECTED_FILE_PATTERNS = [
  /^\.env(\..+)?$/,
  /\.(jks|keystore|p12|pfx|p8|mobileprovision)$/i,
  /(service-?account|firebase-adminsdk|google-play).*\.json$/i,
  /\.(java|kt|swift|mm?)$/,
  /\.entitlements$/,
  /\.rules(\.json)?$/,
];
const RES_XML_PATH = /(^|[\\/])src[\\/][^\\/]+[\\/]res[\\/]xml[\\/][^\\/]+\.xml$/;

/** Used for `--changed-files`, which must only hand rules the file kinds a full scan would collect. */
export function isCollectedFile(filePath: string): boolean {
  const name = basename(filePath);
  // Templates and the public Android debug keystore are never reported, in any scan mode
  if (/^\.env\..*\.(example|sample|template|dist|defaults|schema)$/i.test(name)) return false;
  if (/\.(example|sample|template|dist|defaults|schema)$/i.test(name) && name.startsWith('.env')) return false;
  if (name.toLowerCase() === 'debug.keystore') return false;
  return (
    /\.(js|jsx|ts|tsx)$/.test(name) ||
    COLLECTED_FILE_NAMES.has(name) ||
    COLLECTED_FILE_PATTERNS.some(p => p.test(name)) ||
    RES_XML_PATH.test(filePath)
  );
}

export async function walkProjectFiles(
  rootDir: string,
  additionalIgnore: string[] = [],
  options: WalkOptions = {}
): Promise<FileGroup> {
  const resolvedRoot = resolve(rootDir);

  const patterns = {
    js: ['**/*.{js,jsx,ts,tsx}'],
    json: ['**/app.json', '**/app.config.json', '**/package.json', '**/eas.json'],
    xml: ['**/AndroidManifest.xml', '**/network_security_config.xml'],
    plist: ['**/Info.plist'],
    env: ['**/.env', '**/.env.*'],
    gradle: ['**/build.gradle', '**/build.gradle.kts'],
    gradleProperties: ['**/gradle.properties'],
    registry: ['**/.npmrc', '**/.yarnrc.yml'],
    credentials: [
      '**/*.{jks,keystore,p12,pfx,p8,mobileprovision}',
      '**/*{service-account,serviceaccount,service_account,firebase-adminsdk,google-play}*.json',
    ],
    native: ['**/*.{java,kt,swift,m,mm}'],
    entitlements: ['**/*.entitlements'],
    firebase: ['**/*.rules', '**/*.rules.json', '**/firebase.json'],
    lockfiles: ['**/package-lock.json', '**/npm-shrinkwrap.json', '**/yarn.lock', '**/pnpm-lock.yaml'],
    credentialProperties: ['**/sentry.properties', '**/keystore.properties', '**/signing.properties', '**/credentials.json'],
    resXml: ['**/src/*/res/xml/*.xml'],
  };

  // Extra excludes for native sources (vendored dependencies, build output, test targets)
  const nativeIgnore = [
    '**/Pods/**',
    '**/.gradle/**',
    '**/DerivedData/**',
    '**/Carthage/**',
    '**/*.framework/**',
    '**/*.xcframework/**',
    '**/src/{test,androidTest,testDebug,testRelease}/**',
    '**/*Tests/**',
    '**/*UITests/**',
    '**/*Test.{java,kt}',
    '**/*Tests.{swift,m,mm}',
  ];

  const defaultIgnore = [
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
    '**/.expo/**',
    '**/android/build/**',
    '**/ios/build/**',
    '**/.git/**',
    '**/coverage/**',
    '**/*.test.js',
    '**/*.test.ts',
    '**/*.test.jsx',
    '**/*.test.tsx',
    '**/*.spec.js',
    '**/*.spec.ts',
    '**/*.spec.jsx',
    '**/*.spec.tsx',
    '**/__tests__/**',
    '**/__mocks__/**',
    '**/e2e/**',
    '**/fixtures/**',
    '**/__fixtures__/**',
    '**/mocks/**',
    '**/*.stories.{js,jsx,ts,tsx}',
    '**/tests/**',
    '**/test/**',
    '**/*.e2e.js',
    '**/*.e2e.ts',
    // Android debug source sets never ship in release builds
    '**/src/debug/**',
    '**/src/debugOptimized/**',
  ];

  const ignore = [...defaultIgnore, ...additionalIgnore];

  const [jsFiles, jsonFiles, xmlFiles, plistFiles, envCandidates, gradleBuildFiles, gradlePropCandidates, registryCandidates, credentialCandidates, nativeFiles, entitlementFiles, firebaseRuleFiles, lockfiles, credentialPropCandidates, resXmlCandidates] = await Promise.all([
    fg(patterns.js, { cwd: resolvedRoot, ignore, absolute: true }),
    fg(patterns.json, { cwd: resolvedRoot, ignore, absolute: true }),
    fg(patterns.xml, { cwd: resolvedRoot, ignore, absolute: true }),
    fg(patterns.plist, { cwd: resolvedRoot, ignore, absolute: true }),
    fg(patterns.env, { cwd: resolvedRoot, ignore, absolute: true, dot: true }),
    fg(patterns.gradle, { cwd: resolvedRoot, ignore, absolute: true }),
    fg(patterns.gradleProperties, { cwd: resolvedRoot, ignore, absolute: true }),
    fg(patterns.registry, { cwd: resolvedRoot, ignore, absolute: true, dot: true }),
    fg(patterns.credentials, { cwd: resolvedRoot, ignore, absolute: true, caseSensitiveMatch: false }),
    fg(patterns.native, { cwd: resolvedRoot, ignore: [...ignore, ...nativeIgnore], absolute: true }),
    fg(patterns.entitlements, { cwd: resolvedRoot, ignore, absolute: true }),
    fg(patterns.firebase, { cwd: resolvedRoot, ignore, absolute: true }),
    fg(patterns.lockfiles, { cwd: resolvedRoot, ignore, absolute: true }),
    fg(patterns.credentialProperties, { cwd: resolvedRoot, ignore, absolute: true }),
    fg(patterns.resXml, { cwd: resolvedRoot, ignore, absolute: true }),
  ]);

  // Files that are routinely git-ignored locally are only reported when git tracks them
  const [gradleProperties, registryFiles, credentialFiles, credentialPropertyFiles] = await Promise.all([
    filterGitTracked(gradlePropCandidates, resolvedRoot),
    filterGitTracked(registryCandidates, resolvedRoot),
    filterGitTracked(credentialCandidates.filter(isCollectedFile), resolvedRoot),
    filterGitTracked(credentialPropCandidates, resolvedRoot),
  ]);

  const envCollected = envCandidates.filter(isCollectedFile);
  const envFiles = await filterGitTracked(envCollected, resolvedRoot);

  // Without git these checks silently do nothing: let the caller say so
  if (options.onUnverifiedFiles && !(await isGitRepository(resolvedRoot))) {
    const unverified = new Set([
      ...envCollected,
      ...gradlePropCandidates,
      ...registryCandidates,
      ...credentialCandidates.filter(isCollectedFile),
      ...credentialPropCandidates,
    ]);
    if (unverified.size > 0) options.onUnverifiedFiles(unverified.size);
  }

  const group: FileGroup = {
    jsFiles,
    jsonFiles,
    xmlFiles,
    plistFiles,
    envFiles,
    gradleFiles: [...gradleBuildFiles, ...gradleProperties],
    registryFiles,
    credentialFiles,
    nativeFiles,
    entitlementFiles,
    firebaseRuleFiles,
    lockfiles,
    credentialPropertyFiles,
    // network_security_config.xml is already collected as an xml file
    resXmlFiles: resXmlCandidates.filter(f => basename(f) !== 'network_security_config.xml'),
  };

  if (options.respectGitignore === false) return group;

  // One git call for every group; tracked files survive even when an ignore pattern matches them
  const all = Object.values(group).flat();
  const kept = new Set(await filterGitIgnored(all, resolvedRoot));
  if (kept.size === all.length) return group;
  const keep = (files: string[]) => files.filter(f => kept.has(f));
  return Object.fromEntries(
    Object.entries(group).map(([key, files]) => [key, keep(files)])
  ) as unknown as FileGroup;
}

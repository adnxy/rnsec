import { join } from 'path';
import { readFileContent } from './fileUtils.js';
import { parseJsonSafe } from '../core/astParser.js';

const read = async (path: string): Promise<string | undefined> => {
  try {
    return await readFileContent(path);
  } catch {
    return undefined;
  }
};

/** Remove `//` and block comments (naively; Gradle files rarely hold `//` inside strings next to a sdk key). */
const stripComments = (code: string): string => code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

/** `targetSdk 34`, `targetSdkVersion 34`, `targetSdk = 34`, `targetSdkVersion = 34`, `targetSdkVersion(34)` */
const LITERAL = /\btargetSdk(?:Version)?\s*(?:=|\()?\s*(\d{2,3})\b/;
/** Any other `targetSdk...` assignment (a reference such as `rootProject.ext.targetSdkVersion`) */
const REFERENCE = /\btargetSdk(?:Version)?\b/;

function fromGradle(code: string): { value?: number; reference: boolean } {
  const clean = stripComments(code);
  const literal = LITERAL.exec(clean);
  if (literal) return { value: Number(literal[1]), reference: false };
  return { reference: REFERENCE.test(clean) };
}

/**
 * Resolve the Android targetSdkVersion once per scan. First hit wins:
 * 1. `android/app/build.gradle(.kts)` (or `app/build.gradle(.kts)` when the root is the android folder)
 *    with a literal `targetSdkVersion 34` / `targetSdk = 34` / `targetSdkVersion = 34`
 * 2. when that file only references a variable (`rootProject.ext.targetSdkVersion`), the literal in
 *    `android/build.gradle(.kts)` (`ext { targetSdkVersion = 35 }`) or `build.gradle(.kts)`
 * 3. `expo-build-properties` plugin `android.targetSdkVersion` in `app.json` / `app.config.json`
 * 4. `<uses-sdk android:targetSdkVersion="..">` in `android/app/src/main/AndroidManifest.xml`
 * Undefined when none of them yields a number.
 */
export async function resolveAndroidTargetSdk(rootDir: string): Promise<number | undefined> {
  const appDirs = [join(rootDir, 'android', 'app'), join(rootDir, 'app')];
  const topDirs = [join(rootDir, 'android'), rootDir];

  let needsRoot = false;
  for (const dir of appDirs) {
    for (const name of ['build.gradle', 'build.gradle.kts']) {
      const code = await read(join(dir, name));
      if (code === undefined) continue;
      const r = fromGradle(code);
      if (r.value !== undefined) return r.value;
      needsRoot ||= r.reference;
    }
  }
  if (needsRoot) {
    for (const dir of topDirs) {
      for (const name of ['build.gradle', 'build.gradle.kts']) {
        const code = await read(join(dir, name));
        if (code === undefined) continue;
        const r = fromGradle(code);
        if (r.value !== undefined) return r.value;
      }
    }
  }

  for (const name of ['app.json', 'app.config.json']) {
    const config = parseJsonSafe((await read(join(rootDir, name))) ?? '');
    const plugins = config?.expo?.plugins ?? config?.plugins;
    if (!Array.isArray(plugins)) continue;
    for (const plugin of plugins) {
      if (!Array.isArray(plugin) || plugin[0] !== 'expo-build-properties') continue;
      const value = Number(plugin[1]?.android?.targetSdkVersion);
      if (Number.isInteger(value) && value > 0) return value;
    }
  }

  for (const dir of appDirs) {
    const manifest = await read(join(dir, 'src', 'main', 'AndroidManifest.xml'));
    const m = manifest && /<uses-sdk\b[^>]*android:targetSdkVersion\s*=\s*"(\d+)"/.exec(manifest);
    if (m) return Number(m[1]);
  }
  return undefined;
}

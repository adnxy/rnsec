import { Linking, Platform, Alert } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

enum Endpoint {
  Primary = 'ws://api.example-corp.com/socket',
  Fallback = 1,
  'quoted-member' = 2,
}

declare const dynamicKey: string;
const symbolKey = Symbol('k');
const rest = { token: 'abc' };

// numeric, computed, spread, object-valued and template-literal keys and values
export const config = {
  1: 'ws://api.example-corp.com/numeric',
  0x10: 'http://api.example-corp.com/hex',
  1n: 'bigint-key',
  [dynamicKey]: 'ws://api.example-corp.com/computed',
  [`tpl_${dynamicKey}`]: 'http://api.example-corp.com/tpl',
  [symbolKey]: 'x',
  ['literal-computed']: 'ws://api.example-corp.com/lc',
  ...rest,
  ...(dynamicKey ? { password: 'hunter2hunter2' } : {}),
  url: 'ws://api.example-corp.com/url',
  endpoint: `ws://api.example-corp.com/${dynamicKey}`,
  nested: { 2: { apiUrl: 'http://api.example-corp.com/nested' }, timeout: { ms: 1 } },
  get 3() { return 'x'; },
  set 4(v: string) { void v; },
  async 5() { return fetch(`http://api.example-corp.com/${dynamicKey}`); },
  *6() { yield 1; },
};

class Store {
  static 7 = 'ws://api.example-corp.com/static';
  [dynamicKey] = 'computed field';
  'quoted' = 'x';
  #private = 'secret';
  @observable 8 = 1;
  encrypt(data: string) { return data; }
  async load(this: Store, ...args: unknown[]) {
    const stored = await AsyncStorage?.getItem?.(`user_${args[0]}`);
    const opts = { [`k${args.length}`]: stored, 9: stored, ...(stored ? { token: stored } : {}) };
    await AsyncStorage.setItem?.('auth_token', JSON.stringify(opts));
    return opts?.[9]?.length ?? 0;
  }
}

function observable(target: any, key: string | symbol) { void target; void key; }

export async function run(input?: { url?: string }) {
  await Linking.openURL(input?.url ?? `https://example-corp.com/${Platform.OS}`);
  const ws = new WebSocket(`ws://api.example-corp.com/${input?.url}`);
  new WebSocket(config[1] as string);
  fetch(input!.url!, { 1: 2, [`x`]: 3 } as any);
  console.log(`token ${input?.url}`, { 1: 'a', [dynamicKey]: 'b' });
  Alert.alert('Error', (new Error('x') as any)?.message);
  try { ws.close(); } catch (e: any) { Alert.alert('Error', e?.message); }
  return Endpoint.Primary;
}

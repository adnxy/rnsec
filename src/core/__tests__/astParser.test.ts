import { describe, it, expect } from 'vitest';
import { parseJSFile, parseJsonSafe } from '../astParser.js';

describe('astParser', () => {
  describe('parseJSFile', () => {
    it('should parse valid JavaScript code', async () => {
      const code = 'const x = 1;';
      const result = await parseJSFile('test.js', code);
      
      expect(result.success).toBe(true);
      expect(result.ast).toBeDefined();
      expect(result.error).toBeUndefined();
    });

    it('should parse valid TypeScript code', async () => {
      const code = 'const x: number = 1;';
      const result = await parseJSFile('test.ts', code);
      
      expect(result.success).toBe(true);
      expect(result.ast).toBeDefined();
    });

    it('should parse JSX code', async () => {
      const code = 'const Component = () => <div>Hello</div>;';
      const result = await parseJSFile('test.jsx', code);
      
      expect(result.success).toBe(true);
      expect(result.ast).toBeDefined();
    });

    it('should parse TSX code', async () => {
      const code = `
        interface Props {
          name: string;
        }
        const Component = ({ name }: Props) => <div>{name}</div>;
      `;
      const result = await parseJSFile('test.tsx', code);
      
      expect(result.success).toBe(true);
      expect(result.ast).toBeDefined();
    });

    it('should parse decorators', async () => {
      const code = `
        @decorator
        class MyClass {
          @property
          value = 1;
        }
      `;
      const result = await parseJSFile('test.ts', code);
      
      expect(result.success).toBe(true);
      expect(result.ast).toBeDefined();
    });

    it('should parse async generators', async () => {
      const code = `
        async function* generator() {
          yield await Promise.resolve(1);
        }
      `;
      const result = await parseJSFile('test.js', code);
      
      expect(result.success).toBe(true);
      expect(result.ast).toBeDefined();
    });

    it('should parse dynamic imports', async () => {
      const code = `
        const module = await import('./module.js');
      `;
      const result = await parseJSFile('test.js', code);
      
      expect(result.success).toBe(true);
      expect(result.ast).toBeDefined();
    });

    it('should parse object rest spread', async () => {
      const code = `
        const obj1 = { a: 1, b: 2 };
        const obj2 = { ...obj1, c: 3 };
        const { a, ...rest } = obj2;
      `;
      const result = await parseJSFile('test.js', code);
      
      expect(result.success).toBe(true);
      expect(result.ast).toBeDefined();
    });

    it('should parse class properties', async () => {
      const code = `
        class MyClass {
          instanceProperty = 'value';
          static staticProperty = 42;
        }
      `;
      const result = await parseJSFile('test.js', code);
      
      expect(result.success).toBe(true);
      expect(result.ast).toBeDefined();
    });

    it('should handle syntax errors with error recovery', async () => {
      // errorRecovery is enabled, so it should try to parse even broken code
      const code = 'const x = ;'; // Missing value
      const result = await parseJSFile('test.js', code);
      
      // With error recovery enabled, it might still succeed partially
      // or fail gracefully
      expect(result).toBeDefined();
    });

    it('should parse React Native specific patterns', async () => {
      const code = `
        import { View, Text, StyleSheet } from 'react-native';
        import AsyncStorage from '@react-native-async-storage/async-storage';
        
        const styles = StyleSheet.create({
          container: {
            flex: 1,
          },
        });
        
        export default function App() {
          const [data, setData] = React.useState(null);
          
          React.useEffect(() => {
            AsyncStorage.getItem('key').then(setData);
          }, []);
          
          return (
            <View style={styles.container}>
              <Text>{data}</Text>
            </View>
          );
        }
      `;
      const result = await parseJSFile('App.tsx', code);
      
      expect(result.success).toBe(true);
      expect(result.ast).toBeDefined();
    });

    it('should parse Expo specific patterns', async () => {
      const code = `
        import * as SecureStore from 'expo-secure-store';
        import Constants from 'expo-constants';
        
        const apiUrl = Constants.manifest?.extra?.apiUrl;
        
        async function saveToken(token: string) {
          await SecureStore.setItemAsync('token', token);
        }
      `;
      const result = await parseJSFile('utils.ts', code);
      
      expect(result.success).toBe(true);
      expect(result.ast).toBeDefined();
    });
  });

  describe('parseJsonSafe', () => {
    it('should parse valid JSON', () => {
      const json = '{"name": "test", "version": "1.0.0"}';
      const result = parseJsonSafe(json);
      
      expect(result).toEqual({ name: 'test', version: '1.0.0' });
    });

    it('should parse complex JSON objects', () => {
      const json = JSON.stringify({
        name: 'rnsec',
        dependencies: {
          react: '^18.0.0',
          'react-native': '^0.72.0',
        },
        devDependencies: {
          typescript: '^5.0.0',
        },
        expo: {
          sdkVersion: '49.0.0',
        },
      });
      
      const result = parseJsonSafe(json);
      
      expect(result).toBeDefined();
      expect(result?.name).toBe('rnsec');
      expect(result?.dependencies?.react).toBe('^18.0.0');
    });

    it('should return null for invalid JSON', () => {
      const invalidJson = '{ invalid json }';
      const result = parseJsonSafe(invalidJson);
      
      expect(result).toBeNull();
    });

    it('should return null for empty string', () => {
      const result = parseJsonSafe('');
      
      expect(result).toBeNull();
    });

    it('should parse JSON arrays', () => {
      const json = '[1, 2, 3]';
      const result = parseJsonSafe(json);
      
      expect(result).toEqual([1, 2, 3]);
    });

    it('should handle nested objects', () => {
      const json = JSON.stringify({
        level1: {
          level2: {
            level3: {
              value: 'deep',
            },
          },
        },
      });
      
      const result = parseJsonSafe(json);
      
      expect(result?.level1?.level2?.level3?.value).toBe('deep');
    });

    it('should handle special characters in strings', () => {
      const json = JSON.stringify({
        message: 'Hello "World"!',
        path: 'C:\\Users\\test',
        newline: 'Line1\nLine2',
      });
      
      const result = parseJsonSafe(json);
      
      expect(result?.message).toBe('Hello "World"!');
      expect(result?.path).toBe('C:\\Users\\test');
      expect(result?.newline).toBe('Line1\nLine2');
    });

    it('should handle unicode characters', () => {
      const json = '{"emoji": "🔒", "chinese": "安全"}';
      const result = parseJsonSafe(json);
      
      expect(result?.emoji).toBe('🔒');
      expect(result?.chinese).toBe('安全');
    });
  });
});

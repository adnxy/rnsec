import Config from 'react-native-config';
import { SUPABASE_SERVICE_ROLE_KEY, API_URL } from '@env';

export const stripe = process.env.EXPO_PUBLIC_STRIPE_SECRET_KEY;
export const again = process.env.EXPO_PUBLIC_STRIPE_SECRET_KEY;
export const enc = process.env['EXPO_PUBLIC_ENCRYPTION_KEY'];
const { EXPO_PUBLIC_DB_PASSWORD } = process.env;
export const priv = Config.PRIVATE_KEY;
export const keep = [SUPABASE_SERVICE_ROLE_KEY, API_URL, EXPO_PUBLIC_DB_PASSWORD];

import React, { useEffect } from 'react';
import * as Notifications from 'expo-notifications';
import AsyncStorage from '@react-native-async-storage/async-storage';

// PUSH_NOTIFICATION_SENSITIVE_DATA - Rule should detect this
export function NotificationHandler() {
  useEffect(() => {
    const subscription = Notifications.addNotificationReceivedListener((notification) => {
      // Logging notification data in production
      console.log('Notification data:', notification.request.content.data);

      // Storing sensitive notification data insecurely
      AsyncStorage.setItem('last_token', notification.request.content.data.token);
    });

    return () => subscription.remove();
  }, []);

  return null;
}

import React, { useEffect } from 'react';
import * as Notifications from 'expo-notifications';
import * as SecureStore from 'expo-secure-store';

// SAFE: Notification handler that does NOT log data and uses secure storage
export function NotificationHandler() {
  useEffect(() => {
    const subscription = Notifications.addNotificationReceivedListener((notification) => {
      // Only process notification type, not sensitive data
      const type = notification.request.content.data?.type;

      if (type === 'update') {
        refreshContent();
      }
    });

    return () => subscription.remove();
  }, []);

  return null;
}

function refreshContent() {
  // Refresh UI content
}

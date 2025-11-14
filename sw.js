// sw.js - Service Worker for Push Notifications

self.addEventListener('push', function(event) {
    console.log('Received a push message:', event);

    // Parse the push payload (JSON string)
    let notificationData = {};
    if (event.data) {
        try {
            notificationData = event.data.json();
        } catch (e) {
            console.error('Error parsing push data:', e);
            // Fallback if data is not JSON
            notificationData.title = 'New Message';
            notificationData.body = event.data.text();
        }
    } else {
        // Fallback if no data is sent
        notificationData.title = 'Notification';
        notificationData.body = 'You have a new notification.';
    }

    const title = notificationData.title || 'New Message';
    const body = notificationData.body || 'Click to view';

    const options = {
        body: body,
        icon: '/static/favicon.ico', // Add a favicon.ico to your static folder
        badge: '/static/badge.png',  // Optional: Add a small badge icon
        tag: 'kryonix-chat-message', // Tag to group notifications
        renotify: true,              // Allow multiple notifications with same tag
        requireInteraction: false,   // Auto-dismiss after a while (unless clicked)
        data: {
            url: '/chat' // Default URL to open on click
        }
    };

    // Show the notification
    event.waitUntil(
        self.registration.showNotification(title, options)
    );
});

self.addEventListener('notificationclick', function(event) {
    console.log('Notification clicked:', event.notification);
    event.notification.close(); // Close the notification

    // Open the chat page (or a specific chat if data contains more info)
    event.waitUntil(
        clients.openWindow(event.notification.data.url || '/chat')
    );
});

self.addEventListener('pushsubscriptionchange', function(event) {
    console.log('Push subscription expired or changed:', event);
    // This event fires if the subscription expires or changes (e.g., browser updates keys)
    // You should re-subscribe and send the new subscription to your server here.
    event.waitUntil(
        // Example logic (you'd need to implement the re-subscribe and send part)
        // navigator.serviceWorker.register('/sw.js')
        //     .then(registration => registration.pushManager.subscribe(...))
        //     .then(newSubscription => sendSubscriptionToBackend(newSubscription))
    );
});
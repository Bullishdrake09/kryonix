// Service Worker for push notifications
self.addEventListener('push', function(event) {
    const data = event.data.json();
    
    const options = {
        body: data.body,
        icon: data.icon || '/static/default-avatar.png',
        badge: '/static/badge-icon.png',
        tag: data.tag || 'kryonix-message',
        requireInteraction: false,
        data: {
            room: data.room,
            username: data.username
        }
    };
    
    event.waitUntil(
        self.registration.showNotification(data.title, options)
    );
});

self.addEventListener('notificationclick', function(event) {
    event.notification.close();
    
    event.waitUntil(
        clients.openWindow('/')
    );
});
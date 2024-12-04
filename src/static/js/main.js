// Initialize Socket.IO connection
const socket = io();

// Global notification settings
let notificationSound = new Audio('/static/sounds/notification.mp3');
let notificationPermission = false;

// Request notification permission
if ('Notification' in window) {
    Notification.requestPermission().then(function(permission) {
        notificationPermission = permission === 'granted';
    });
}

// Show desktop notification
function showNotification(title, options) {
    if (notificationPermission && document.hidden) {
        new Notification(title, options);
    }
}

// Play notification sound
function playNotificationSound() {
    if (document.hidden) {
        notificationSound.play().catch(() => {});
    }
}

// Format timestamp
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

// Handle errors
function handleError(error) {
    console.error('Error:', error);
    // Show error message to user
    const errorDiv = document.createElement('div');
    errorDiv.className = 'mb-4 p-4 rounded-lg bg-red-100 text-red-700';
    errorDiv.textContent = error.message || 'An error occurred';
    document.querySelector('.container').prepend(errorDiv);
    
    // Remove error message after 5 seconds
    setTimeout(() => errorDiv.remove(), 5000);
}

class NotificationManager {
    constructor() {
        this.lastMessageTimes = {};
        this.notificationsEnabled = false;
        this.setupNotifications();
    }

    setupNotifications() {
        if ('Notification' in window) {
            if (Notification.permission === 'granted') {
                this.notificationsEnabled = true;
            } else if (Notification.permission !== 'denied') {
                Notification.requestPermission().then(permission => {
                    this.notificationsEnabled = permission === 'granted';
                });
            }
        }
    }

    async checkNewMessages() {
        try {
            const response = await fetch('/check_messages');
            const data = await response.json();
            
            if (data.new_messages) {
                data.new_messages.forEach(message => {
                    const messageTime = new Date(message.timestamp).getTime();
                    const lastTime = this.lastMessageTimes[message.sender_id] || 0;

                    if (messageTime > lastTime && message.sender_id !== currentUserId) {
                        this.lastMessageTimes[message.sender_id] = messageTime;
                        this.showNotification(message);
                    }
                });
            }
        } catch (error) {
            console.error('Error checking messages:', error);
        }
    }

    showNotification(message) {
        // Show browser notification if enabled
        if (this.notificationsEnabled) {
            const notification = new Notification('New Message', {
                body: `${message.sender_name}: ${message.content}`,
                icon: '/static/images/chat-icon.png'
            });

            notification.onclick = () => {
                window.focus();
                if (message.chat_type === 'private') {
                    window.location.href = `/chat?friend_id=${message.sender_id}`;
                } else {
                    window.location.href = `/chat?group_id=${message.group_id}`;
                }
            };
        }

        // Show in-app notification
        this.showInAppNotification(message);
        
        // Update page title if not focused
        if (!document.hasFocus()) {
            this.updatePageTitle('New Message');
        }
    }

    showInAppNotification(message) {
        const toastContainer = document.querySelector('.toast-container');
        const toast = document.createElement('div');
        toast.className = 'toast';
        
        const content = `
            <div class="toast-header">
                <strong class="me-auto">${message.sender_name}</strong>
                <small>${this.formatTime(new Date(message.timestamp))}</small>
            </div>
            <div class="toast-body">
                ${message.content}
            </div>
        `;
        
        toast.innerHTML = content;
        toastContainer.appendChild(toast);

        // Add visual highlight animation
        toast.style.animation = 'slideIn 0.3s ease-out';
        
        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease-out';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    updatePageTitle(text) {
        const originalTitle = document.title;
        let isOriginal = false;
        
        const interval = setInterval(() => {
            document.title = isOriginal ? originalTitle : text;
            isOriginal = !isOriginal;
        }, 1000);

        // Reset title when window gets focus
        window.addEventListener('focus', () => {
            clearInterval(interval);
            document.title = originalTitle;
        }, { once: true });
    }

    formatTime(date) {
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
}

// Initialize notification manager
const notificationManager = new NotificationManager();

// Check for new messages every 5 seconds when window is not focused
setInterval(() => {
    if (!document.hasFocus()) {
        notificationManager.checkNewMessages();
    }
}, 5000);

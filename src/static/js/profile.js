// Profile elements
const avatarUpload = document.getElementById('avatar-upload');
const soundToggle = document.getElementById('soundToggle');
const desktopNotifToggle = document.getElementById('desktopNotifToggle');

// Handle avatar upload
avatarUpload.addEventListener('change', function(event) {
    const file = event.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('avatar', file);

    fetch('/profile/avatar', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Update avatar preview
            document.querySelector('img[alt="Profile Picture"]').src = data.avatar_url;
            showMessage('Avatar updated successfully', 'success');
        } else {
            throw new Error(data.error || 'Failed to update avatar');
        }
    })
    .catch(error => {
        showMessage(error.message, 'error');
    });
});

// Handle notification toggles
soundToggle.addEventListener('click', function() {
    const enabled = !this.classList.contains('bg-indigo-600');
    updateNotificationSetting('notification_sound', enabled);
});

desktopNotifToggle.addEventListener('click', function() {
    const enabled = !this.classList.contains('bg-indigo-600');
    if (enabled && 'Notification' in window) {
        Notification.requestPermission().then(function(permission) {
            if (permission === 'granted') {
                updateNotificationSetting('desktop_notifications', true);
            }
        });
    } else {
        updateNotificationSetting('desktop_notifications', enabled);
    }
});

// Update notification settings
function updateNotificationSetting(type, enabled) {
    const data = {};
    data[type] = enabled;
    
    fetch('/profile/settings', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            const toggle = type === 'notification_sound' ? soundToggle : desktopNotifToggle;
            toggle.classList.toggle('bg-gray-200');
            toggle.classList.toggle('bg-indigo-600');
            
            const span = toggle.querySelector('span');
            span.classList.toggle('translate-x-5');
            
            const settingName = type === 'notification_sound' ? 'Sound' : 'Desktop';
            showMessage(`${settingName} notifications ${enabled ? 'enabled' : 'disabled'}`, 'success');
        } else {
            throw new Error(data.error || 'Failed to update notification settings');
        }
    })
    .catch(error => {
        showMessage(error.message, 'error');
    });
}

// Show message
function showMessage(message, type = 'success') {
    const messageDiv = document.createElement('div');
    messageDiv.className = `mb-4 p-4 rounded-lg ${type === 'success' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`;
    messageDiv.textContent = message;
    
    const container = document.querySelector('.container');
    container.insertBefore(messageDiv, container.firstChild);
    
    setTimeout(() => messageDiv.remove(), 3000);
}

// Handle bio updates
const bioForm = document.querySelector('form[action="/profile/update"]');
if (bioForm) {
    bioForm.addEventListener('submit', function(event) {
        event.preventDefault();
        this.submit();
    });
}

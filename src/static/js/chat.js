// Chat elements
const messagesArea = document.getElementById('messagesArea');
const messageInput = document.getElementById('messageInput');
const sendBtn = document.getElementById('sendBtn');
const attachmentBtn = document.getElementById('attachmentBtn');
const emojiBtn = document.getElementById('emojiBtn');
const typingIndicator = document.getElementById('typingIndicator');

// Current chat state
let currentChat = {
    type: null, // 'direct' or 'group'
    id: null,
    name: null
};

// Initialize chat
function initializeChat() {
    // Join user's room for private messages
    socket.emit('join', { room: `user_${currentUser.id}` });
    
    // Load initial messages
    loadMessages();
    
    // Setup event listeners
    setupEventListeners();
}

// Setup event listeners
function setupEventListeners() {
    // Message input events
    messageInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    messageInput.addEventListener('input', function() {
        socket.emit('typing', {
            recipient_id: currentChat.type === 'direct' ? currentChat.id : null,
            group_id: currentChat.type === 'group' ? currentChat.id : null,
            is_typing: true
        });
    });

    // Send button click
    sendBtn.addEventListener('click', sendMessage);

    // Attachment button click
    attachmentBtn.addEventListener('click', function() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = 'image/*,video/*,audio/*,.pdf,.doc,.docx,.txt';
        input.onchange = handleFileSelect;
        input.click();
    });

    // Socket events
    socket.on('new_message', handleNewMessage);
    socket.on('typing', handleTypingIndicator);
    socket.on('status_change', handleStatusChange);
}

// Load messages
function loadMessages() {
    if (!currentChat.id) return;
    
    fetch(`/messages/${currentChat.type}/${currentChat.id}`)
        .then(response => response.json())
        .then(messages => {
            messagesArea.innerHTML = '';
            messages.forEach(message => displayMessage(message));
            scrollToBottom();
        })
        .catch(handleError);
}

// Send message
function sendMessage() {
    const content = messageInput.value.trim();
    if (!content) return;

    const messageData = {
        content: content,
        recipient_id: currentChat.type === 'direct' ? currentChat.id : null,
        group_id: currentChat.type === 'group' ? currentChat.id : null
    };

    socket.emit('new_message', messageData);
    messageInput.value = '';
}

// Display message
function displayMessage(message) {
    const isOwn = message.sender_id === currentUser.id;
    const messageElement = document.createElement('div');
    messageElement.className = `flex ${isOwn ? 'justify-end' : 'justify-start'} mb-4`;

    messageElement.innerHTML = `
        <div class="max-w-lg">
            ${!isOwn ? `<div class="text-sm text-gray-500 mb-1">${message.sender_name}</div>` : ''}
            <div class="flex items-end">
                ${!isOwn ? `
                    <img src="${message.sender_avatar || '/static/img/default-avatar.png'}" 
                         alt="${message.sender_name}"
                         class="w-8 h-8 rounded-full mr-2">
                ` : ''}
                <div class="${isOwn ? 'bg-indigo-500 text-white' : 'bg-gray-200 text-gray-800'} rounded-lg px-4 py-2">
                    ${formatMessageContent(message)}
                </div>
            </div>
            <div class="text-xs text-gray-500 mt-1 ${isOwn ? 'text-right' : ''}">
                ${formatTimestamp(message.timestamp)}
            </div>
        </div>
    `;

    messagesArea.appendChild(messageElement);
    scrollToBottom();
}

// Format message content based on type
function formatMessageContent(message) {
    switch (message.message_type) {
        case 'image':
            return `<img src="${message.file_url}" alt="Image" class="max-w-sm rounded-lg cursor-pointer" 
                        onclick="showImagePreview('${message.file_url}')">`;
        case 'video':
            return `<video controls class="max-w-sm rounded-lg">
                        <source src="${message.file_url}" type="video/mp4">
                    </video>`;
        case 'audio':
            return `<audio controls class="max-w-sm">
                        <source src="${message.file_url}" type="audio/mpeg">
                    </audio>`;
        case 'file':
            return `<a href="${message.file_url}" target="_blank" 
                      class="flex items-center text-blue-500 hover:text-blue-700">
                        <i class="fas fa-file-alt mr-2"></i>
                        ${message.content}
                    </a>`;
        default:
            return message.content;
    }
}

// Handle file selection
function handleFileSelect(event) {
    const file = event.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        const messageData = {
            content: file.name,
            file_url: data.file_url,
            file_type: data.file_type,
            message_type: data.message_type,
            recipient_id: currentChat.type === 'direct' ? currentChat.id : null,
            group_id: currentChat.type === 'group' ? currentChat.id : null
        };
        socket.emit('new_message', messageData);
    })
    .catch(handleError);
}

// Handle typing indicator
function handleTypingIndicator(data) {
    if ((currentChat.type === 'direct' && data.user_id === currentChat.id) ||
        (currentChat.type === 'group' && data.group_id === currentChat.id)) {
        if (data.is_typing) {
            typingIndicator.textContent = `${data.username} is typing...`;
            typingIndicator.classList.remove('hidden');
        } else {
            typingIndicator.classList.add('hidden');
        }
    }
}

// Handle status change
function handleStatusChange(data) {
    const statusDot = document.querySelector(`[data-user-id="${data.user_id}"] .status-dot`);
    if (statusDot) {
        statusDot.className = `status-dot ${data.status === 'online' ? 'bg-green-500' : 'bg-gray-500'}`;
    }
}

// Scroll to bottom of messages
function scrollToBottom() {
    messagesArea.scrollTop = messagesArea.scrollHeight;
}

// Initialize chat when page loads
document.addEventListener('DOMContentLoaded', initializeChat);

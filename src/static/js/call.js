// WebRTC configuration
const configuration = {
    iceServers: [
        { urls: 'stun:stun.l.google.com:19302' }
    ]
};

let peerConnection;
let localStream;
let remoteStream;
let callTimer;
let currentCall = {
    id: null,
    type: null,
    status: null
};

// Initialize media devices
async function initializeMediaDevices(type) {
    try {
        const constraints = {
            audio: true,
            video: type === 'video'
        };
        localStream = await navigator.mediaDevices.getUserMedia(constraints);
        document.getElementById('localVideo').srcObject = localStream;
        return true;
    } catch (error) {
        console.error('Error accessing media devices:', error);
        return false;
    }
}

// Start call
async function startCall(userId, type = 'audio') {
    if (await initializeMediaDevices(type)) {
        currentCall = {
            id: userId,
            type: type,
            status: 'outgoing'
        };
        
        createPeerConnection();
        
        // Add local stream to peer connection
        localStream.getTracks().forEach(track => {
            peerConnection.addTrack(track, localStream);
        });
        
        // Create and send offer
        try {
            const offer = await peerConnection.createOffer();
            await peerConnection.setLocalDescription(offer);
            
            socket.emit('call_request', {
                recipient_id: userId,
                call_type: type,
                offer: offer
            });
            
            showCallUI('outgoing');
        } catch (error) {
            console.error('Error creating offer:', error);
            endCall();
        }
    }
}

// Handle incoming call
async function handleIncomingCall(data) {
    currentCall = {
        id: data.caller_id,
        type: data.call_type,
        status: 'incoming'
    };
    
    document.getElementById('callerName').textContent = data.caller_name;
    showCallUI('incoming');
}

// Accept call
async function acceptCall() {
    if (await initializeMediaDevices(currentCall.type)) {
        createPeerConnection();
        
        // Add local stream to peer connection
        localStream.getTracks().forEach(track => {
            peerConnection.addTrack(track, localStream);
        });
        
        try {
            await peerConnection.setRemoteDescription(new RTCSessionDescription(currentCall.offer));
            const answer = await peerConnection.createAnswer();
            await peerConnection.setLocalDescription(answer);
            
            socket.emit('call_accepted', {
                caller_id: currentCall.id,
                answer: answer
            });
            
            showCallUI('active');
            startCallTimer();
        } catch (error) {
            console.error('Error accepting call:', error);
            endCall();
        }
    }
}

// Reject call
function rejectCall() {
    socket.emit('call_rejected', {
        caller_id: currentCall.id
    });
    endCall();
}

// End call
function endCall() {
    socket.emit('call_ended', {
        peer_id: currentCall.id
    });
    
    if (peerConnection) {
        peerConnection.close();
        peerConnection = null;
    }
    
    if (localStream) {
        localStream.getTracks().forEach(track => track.stop());
        localStream = null;
    }
    
    if (remoteStream) {
        remoteStream.getTracks().forEach(track => track.stop());
        remoteStream = null;
    }
    
    if (callTimer) {
        clearInterval(callTimer);
        callTimer = null;
    }
    
    currentCall = {
        id: null,
        type: null,
        status: null
    };
    
    hideCallUI();
}

// Create WebRTC peer connection
function createPeerConnection() {
    peerConnection = new RTCPeerConnection(configuration);
    
    peerConnection.onicecandidate = event => {
        if (event.candidate) {
            socket.emit('ice_candidate', {
                peer_id: currentCall.id,
                candidate: event.candidate
            });
        }
    };
    
    peerConnection.ontrack = event => {
        remoteStream = event.streams[0];
        document.getElementById('remoteVideo').srcObject = remoteStream;
    };
    
    peerConnection.oniceconnectionstatechange = () => {
        if (peerConnection.iceConnectionState === 'disconnected') {
            endCall();
        }
    };
}

// Toggle mute
function toggleMute() {
    if (localStream) {
        const audioTrack = localStream.getAudioTracks()[0];
        audioTrack.enabled = !audioTrack.enabled;
        
        const muteIcon = document.getElementById('muteIcon');
        muteIcon.className = audioTrack.enabled ? 'fas fa-microphone' : 'fas fa-microphone-slash';
    }
}

// Toggle video
function toggleVideo() {
    if (localStream) {
        const videoTrack = localStream.getVideoTracks()[0];
        if (videoTrack) {
            videoTrack.enabled = !videoTrack.enabled;
            
            const videoIcon = document.getElementById('videoIcon');
            videoIcon.className = videoTrack.enabled ? 'fas fa-video' : 'fas fa-video-slash';
        }
    }
}

// Start call timer
function startCallTimer() {
    let seconds = 0;
    const durationElement = document.getElementById('callDuration');
    
    callTimer = setInterval(() => {
        seconds++;
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        durationElement.textContent = `${minutes.toString().padStart(2, '0')}:${remainingSeconds.toString().padStart(2, '0')}`;
    }, 1000);
}

// Show/hide call UI
function showCallUI(type) {
    const modal = document.getElementById('callModal');
    const incomingCall = document.getElementById('incomingCall');
    const activeCall = document.getElementById('activeCall');
    const videoContainer = document.getElementById('videoContainer');
    
    modal.classList.remove('hidden');
    
    switch (type) {
        case 'incoming':
            incomingCall.classList.remove('hidden');
            activeCall.classList.add('hidden');
            break;
        case 'active':
            incomingCall.classList.add('hidden');
            activeCall.classList.remove('hidden');
            if (currentCall.type === 'video') {
                videoContainer.classList.remove('hidden');
            }
            break;
    }
}

function hideCallUI() {
    const modal = document.getElementById('callModal');
    const incomingCall = document.getElementById('incomingCall');
    const activeCall = document.getElementById('activeCall');
    const videoContainer = document.getElementById('videoContainer');
    
    modal.classList.add('hidden');
    incomingCall.classList.add('hidden');
    activeCall.classList.add('hidden');
    videoContainer.classList.add('hidden');
}

// Socket event listeners
socket.on('incoming_call', handleIncomingCall);

socket.on('call_accepted', async data => {
    try {
        await peerConnection.setRemoteDescription(new RTCSessionDescription(data.answer));
        showCallUI('active');
        startCallTimer();
    } catch (error) {
        console.error('Error handling call acceptance:', error);
        endCall();
    }
});

socket.on('call_rejected', () => {
    endCall();
});

socket.on('call_ended', () => {
    endCall();
});

socket.on('ice_candidate', async data => {
    try {
        if (peerConnection) {
            await peerConnection.addIceCandidate(new RTCIceCandidate(data.candidate));
        }
    } catch (error) {
        console.error('Error adding ICE candidate:', error);
    }
});

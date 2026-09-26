// Disable WebRTC at the earliest possible point to prevent STUN/ICE IP leaks outside administrative VPN.
export function blockWebRTC() {
  if (typeof window !== 'undefined') {
    delete (window as any).RTCPeerConnection;
    delete (window as any).webkitRTCPeerConnection;
    delete (window as any).mozRTCPeerConnection;

    if (navigator.mediaDevices) {
      navigator.mediaDevices.getUserMedia = () =>
        Promise.reject(new Error("WebRTC disabled by JOCKY security policy"));
    }
    console.log("[JOCKY SECURITY] WebRTC APIs successfully disabled.");
  }
}

blockWebRTC();

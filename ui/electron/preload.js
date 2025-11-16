const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  invoke: (channel, payload) => ipcRenderer.invoke(channel, payload),
  startStream: (name, args) => ipcRenderer.invoke('stream:start', { name, args }),
  stopStream: (token) => ipcRenderer.invoke('stream:stop', token),
  onStream: (listener) => {
    const handler = (_event, data) => listener(data);
    ipcRenderer.on('stream:event', handler);
    ipcRenderer.send('window:ready');
    return () => ipcRenderer.removeListener('stream:event', handler);
  }
});

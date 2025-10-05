// Secure File Share Application with Server Backend
class SecureFileShareApp {
    constructor() {
        this.currentUser = null;
        this.files = [];
        this.users = [];
        this.token = localStorage.getItem('token') || null;
        
        // Initialize event listeners
        this.initializeEventListeners();
        
        // Check if user is logged in
        this.checkAuthStatus();
    }
    
    initializeEventListeners() {
        // Navigation event listeners
        document.getElementById('login-link')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.showSection('login-section');
        });
        
        document.getElementById('register-link')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.showSection('register-section');
        });
        
        document.getElementById('show-register')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.showSection('register-section');
        });
        
        document.getElementById('show-login')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.showSection('login-section');
        });
        
        document.getElementById('dashboard-link')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.showSection('dashboard-section');
            this.loadDashboardStats();
        });
        
        document.getElementById('upload-link')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.showSection('upload-section');
        });
        
        document.getElementById('files-link')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.showSection('files-section');
            this.loadUserFiles();
        });
        
        document.getElementById('logout-btn')?.addEventListener('click', (e) => {
            e.preventDefault();
            this.logout();
        });
        
        // Form event listeners
        document.getElementById('login-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });
        
        document.getElementById('register-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleRegister();
        });
        
        // File upload event listeners
        const dropZone = document.getElementById('drop-zone');
        const fileInput = document.getElementById('file-input');
        const browseBtn = document.getElementById('browse-btn');
        
        if (dropZone) {
            dropZone.addEventListener('click', () => fileInput.click());
            
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, this.preventDefaults, false);
            });
            
            ['dragenter', 'dragover'].forEach(eventName => {
                dropZone.addEventListener(eventName, () => dropZone.classList.add('drag-over'), false);
            });
            
            ['dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, () => dropZone.classList.remove('drag-over'), false);
            });
            
            dropZone.addEventListener('drop', (e) => this.handleDrop(e), false);
        }
        
        if (fileInput) {
            fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        }
        
        if (browseBtn) {
            browseBtn.addEventListener('click', () => fileInput.click());
        }
        
        // Share modal event listeners
        document.getElementById('share-file-btn')?.addEventListener('click', () => {
            this.shareFileWithUser();
        });
    }
    
    preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    async handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        for (let i = 0; i < files.length; i++) {
            await this.uploadFile(files[i]);
        }
    }
    
    handleFileSelect(e) {
        const files = e.target.files;
        for (let i = 0; i < files.length; i++) {
            this.uploadFile(files[i]);
        }
    }
    
    async uploadFile(file) {
        const progressDiv = document.getElementById('upload-progress');
        const progressBar = progressDiv?.querySelector('.progress-bar');
        const statusText = document.getElementById('upload-status');
        
        if (progressDiv) progressDiv.classList.remove('d-none');
        
        try {
            statusText.textContent = `Uploading ${file.name}...`;
            
            // Create form data to send to server
            const formData = new FormData();
            formData.append('file', file, file.name);
            
            // Send to server (server will handle encryption)
            const response = await fetch('/api/upload', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.token}`
                },
                body: formData
            });
            
            if (response.ok) {
                const result = await response.json();
                statusText.textContent = `Successfully uploaded ${file.name}`;
                this.showAlert('File uploaded successfully!', 'success');
                
                // Reset progress after delay
                setTimeout(() => {
                    if (progressDiv) progressDiv.classList.add('d-none');
                    progressBar.style.width = '0%';
                    statusText.textContent = 'Ready to upload';
                }, 2000);
                
                // Refresh files list if on files section
                if (document.getElementById('files-section').classList.contains('d-none') === false) {
                    this.loadUserFiles();
                }
            } else {
                const error = await response.json();
                statusText.textContent = `Error uploading ${file.name}: ${error.message}`;
                this.showAlert('Upload failed: ' + error.message, 'danger');
            }
        } catch (error) {
            statusText.textContent = `Error uploading ${file.name}: ${error.message}`;
            this.showAlert('Upload failed: ' + error.message, 'danger');
        }
    }
    
    async downloadFile(fileId) {
        try {
            // Create a temporary anchor element to trigger the download
            const link = document.createElement('a');
            // Extract the token from the Bearer format if needed
            let tokenForUrl = this.token;
            if (this.token && this.token.startsWith('Bearer ')) {
                tokenForUrl = this.token.substring(7);
            }
            link.href = `/api/files/${fileId}/download?token=${tokenForUrl}`;
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            this.showAlert('File download started!', 'success');
        } catch (error) {
            this.showAlert('Error downloading file: ' + error.message, 'danger');
        }
    }
    
    async readFileAsArrayBuffer(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsArrayBuffer(file);
        });
    }
    
    arrayBufferToBlob(buffer, mimeType) {
        return new Blob([buffer], { type: mimeType });
    }
    
    generateEncryptionKey() {
        // Generate a random 256-bit key
        const keyArray = new Uint8Array(32); // 256 bits
        crypto.getRandomValues(keyArray);
        return Array.from(keyArray).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    async handleLogin() {
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;
        
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                this.token = data.token;
                this.currentUser = data.user;
                localStorage.setItem('token', this.token);
                
                this.showAuthedNav();
                this.showSection('dashboard-section');
                this.loadDashboardStats();
                this.showAlert('Login successful!', 'success');
            } else {
                this.showAlert(data.message || 'Login failed', 'danger');
            }
        } catch (error) {
            this.showAlert('Login failed: ' + error.message, 'danger');
        }
    }
    
    async handleRegister() {
        const username = document.getElementById('register-username').value;
        const email = document.getElementById('register-email').value;
        const password = document.getElementById('register-password').value;
        const confirmPassword = document.getElementById('register-confirm-password').value;
        
        if (password !== confirmPassword) {
            this.showAlert('Passwords do not match', 'danger');
            return;
        }
        
        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, email, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                this.token = data.token;
                this.currentUser = data.user;
                localStorage.setItem('token', this.token);
                
                this.showAuthedNav();
                this.showSection('dashboard-section');
                this.loadDashboardStats();
                this.showAlert('Registration successful!', 'success');
            } else {
                this.showAlert(data.message || 'Registration failed', 'danger');
            }
        } catch (error) {
            this.showAlert('Registration failed: ' + error.message, 'danger');
        }
    }
    
    checkAuthStatus() {
        if (this.token) {
            // Verify token is still valid
            fetch('/api/protected-endpoint', { // This would be a real endpoint that checks token validity
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            })
            .then(response => {
                if (response.ok) {
                    this.showAuthedNav();
                    this.showSection('dashboard-section');
                    this.loadDashboardStats();
                } else {
                    this.logout();
                }
            })
            .catch(() => {
                this.logout();
            });
        } else {
            this.showSection('login-section');
        }
    }
    
    showAuthedNav() {
        document.getElementById('auth-nav').classList.add('d-none');
        document.getElementById('user-nav').classList.remove('d-none');
        document.getElementById('nav-username').textContent = this.currentUser?.username || 'User';
    }
    
    showUnauthedNav() {
        document.getElementById('auth-nav').classList.remove('d-none');
        document.getElementById('user-nav').classList.add('d-none');
    }
    
    showSection(sectionId) {
        // Hide all sections
        document.querySelectorAll('section').forEach(section => {
            section.classList.add('d-none');
        });
        
        // Show requested section
        document.getElementById(sectionId).classList.remove('d-none');
    }
    
    async loadDashboardStats() {
        if (!this.token) return;
        
        try {
            const response = await fetch('/api/files', {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });
            
            if (response.ok) {
                this.files = await response.json();
                
                // Calculate stats
                const totalFiles = this.files.length;
                const totalStorage = this.files.reduce((sum, file) => sum + (file.size || 0), 0);
                const sharedFiles = this.files.filter(file => file.sharedWith && file.sharedWith.length > 0).length;
                
                // Update dashboard stats
                document.getElementById('total-files').textContent = totalFiles;
                document.getElementById('shared-files').textContent = sharedFiles;
                document.getElementById('total-storage').textContent = this.formatFileSize(totalStorage);
                document.getElementById('recent-activity').textContent = Math.min(5, totalFiles);
            }
        } catch (error) {
            console.error('Error loading dashboard stats:', error);
        }
    }
    
    async loadUserFiles() {
        if (!this.token) return;
        
        try {
            const response = await fetch('/api/files', {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });
            
            if (response.ok) {
                this.files = await response.json();
                this.renderFilesTable();
            }
        } catch (error) {
            console.error('Error loading user files:', error);
        }
    }
    
    renderFilesTable() {
        const tbody = document.getElementById('files-table-body');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        this.files.forEach(file => {
            const row = document.createElement('tr');
            row.className = 'file-row';
            
            // Determine file type for icon
            let iconClass = 'other';
            let typeClass = 'other';
            
            if (file.type?.includes('image')) {
                iconClass = 'img';
                typeClass = 'img';
            } else if (file.type?.includes('pdf')) {
                iconClass = 'pdf';
                typeClass = 'pdf';
            } else if (file.type?.includes('document') || file.type?.includes('word')) {
                iconClass = 'doc';
                typeClass = 'doc';
            } else if (file.type?.includes('text')) {
                iconClass = 'txt';
                typeClass = 'txt';
            }
            
            // Format the date
            const uploadDate = new Date(file.uploaded_at || file.uploadedAt);
            const formattedDate = uploadDate.toLocaleDateString();
            
            // Count shared users
            const sharedCount = file.shared_with ? file.shared_with.length : (file.sharedWith ? file.sharedWith.length : 0);
            
            row.innerHTML = `
                <td>
                    <div class="d-flex align-items-center">
                        <div class="file-icon ${iconClass} me-2">
                            <i class="fas fa-file"></i>
                        </div>
                        <div>
                            <div>${file.original_name || file.originalName || file.filename}</div>
                            <small class="text-muted">
                                <span class="encryption-status" title="End-to-end encrypted"></span>
                                <span class="file-type-badge file-type-${typeClass}">${file.type?.split('/')[1] || file.type || 'file'}</span>
                            </small>
                        </div>
                    </div>
                </td>
                <td>${this.formatFileSize(file.size)}</td>
                <td>${file.type?.split('/')[1] || file.type || 'file'}</td>
                <td>${formattedDate}</td>
                <td>${sharedCount} user${sharedCount !== 1 ? 's' : ''}</td>
                <td class="file-actions">
                    <button class="btn btn-sm btn-outline-primary" onclick="app.downloadFile('${file.id}')" title="Download">
                        <i class="fas fa-download"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-info" onclick="app.shareFile('${file.id}')" title="Share">
                        <i class="fas fa-share-alt"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-secondary" onclick="app.viewFileDetails('${file.id}')" title="Details">
                        <i class="fas fa-info-circle"></i>
                    </button>
                    <button class="btn btn-sm btn-outline-danger" onclick="app.deleteFile('${file.id}')" title="Delete">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            `;
            
            tbody.appendChild(row);
        });
    }
    
    async shareFile(fileId) {
        // Clear previous search results and reset form
        document.getElementById('share-user-email').value = '';
        document.getElementById('user-search-results').innerHTML = '';
        
        // Set the file ID
        document.getElementById('share-file-id').value = fileId;
        
        // Show the modal
        const modal = new bootstrap.Modal(document.getElementById('shareModal'));
        modal.show();
        
        // Add event listener to the email input for real-time search
        const emailInput = document.getElementById('share-user-email');
        emailInput.removeEventListener('input', this.handleUserSearch); // Remove any existing listener
        this.handleUserSearch = this.debounce(this.searchUsersByEmail.bind(this), 300);
        emailInput.addEventListener('input', this.handleUserSearch);
    }
    
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
    
    async searchUsersByEmail(event) {
        const emailQuery = event.target.value.trim();
        const resultsContainer = document.getElementById('user-search-results');
        
        if (emailQuery.length < 2) {
            resultsContainer.innerHTML = '';
            return;
        }
        
        try {
            // Call the server to search for users
            const response = await fetch(`/api/users/search?query=${encodeURIComponent(emailQuery)}`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });
            
            if (response.ok) {
                const matchingUsers = await response.json();
                
                if (matchingUsers.length > 0) {
                    let resultsHtml = '<div class="list-group">';
                    
                    matchingUsers.slice(0, 5).forEach(user => { // Limit to 5 results
                        if (user.id !== this.currentUser.id) { // Exclude current user
                            resultsHtml += `
                                <a href="#" class="list-group-item list-group-item-action user-result" data-user-id="${user.id}">
                                    <div class="d-flex w-100 justify-content-between">
                                        <h6 class="mb-1">${user.username}</h6>
                                        <small>${user.email}</small>
                                    </div>
                                </a>
                            `;
                        }
                    });
                    
                    resultsHtml += '</div>';
                    resultsContainer.innerHTML = resultsHtml;
                    
                    // Add click event listeners to the results
                    document.querySelectorAll('.user-result').forEach(element => {
                        element.addEventListener('click', (e) => {
                            e.preventDefault();
                            const userId = e.target.closest('.user-result').dataset.userId;
                            this.selectUserForSharing(userId);
                        });
                    });
                } else {
                    resultsContainer.innerHTML = '<div class="text-muted">No users found</div>';
                }
            } else {
                resultsContainer.innerHTML = '<div class="text-danger">Error searching users</div>';
            }
        } catch (error) {
            resultsContainer.innerHTML = '<div class="text-danger">Error searching users</div>';
            console.error('Error searching users:', error);
        }
    }
    
    selectUserForSharing(userId) {
        // Find the user from the search results (we'll need to store them temporarily)
        // For now, let's just call the server to get the user details by ID
        this.getUserById(userId).then(user => {
            if (user) {
                // Set the email in the input field to show the selected user
                document.getElementById('share-user-email').value = user.email;
                
                // Clear search results
                document.getElementById('user-search-results').innerHTML = `
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle me-2"></i>
                        Selected: ${user.username} (${user.email})
                    </div>
                `;
                
                // Store the selected user ID in a data attribute
                const emailInput = document.getElementById('share-user-email');
                emailInput.dataset.selectedUserId = userId;
            }
        }).catch(error => {
            console.error('Error getting user by ID:', error);
            this.showAlert('Error selecting user', 'danger');
        });
    }
    
    async getUserById(userId) {
        // This would be a server endpoint to get a specific user by ID
        // For now, we'll have to work with the search results
        // In a real implementation, you'd have an endpoint like /api/users/:id
        return null; // Placeholder
    }
    
    async shareFileWithUser() {
        const fileId = document.getElementById('share-file-id').value;
        const userEmail = document.getElementById('share-user-email').value.trim();
        const selectedUserId = document.getElementById('share-user-email').dataset.selectedUserId;
        const permission = document.getElementById('share-permission').value;
        
        if (!fileId || (!userEmail && !selectedUserId)) {
            this.showAlert('Please enter a user email to share with', 'warning');
            return;
        }
        
        let userId = selectedUserId;
        
        // If we don't have a selected user ID, we'll send the email to the server to resolve
        if (!userId) {
            userId = userEmail; // Send email to server to resolve to user ID
        }
        
        try {
            const response = await fetch(`/api/files/${fileId}/share`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify({ 
                    userId: userId, 
                    permission: permission,
                    isEmail: !selectedUserId // Indicate if this is an email lookup
                })
            });
            
            const result = await response.json();
            
            if (response.ok) {
                this.showAlert('File shared successfully!', 'success');
                
                // Close modal
                const modal = bootstrap.Modal.getInstance(document.getElementById('shareModal'));
                modal.hide();
                
                // Refresh files list
                this.loadUserFiles();
            } else {
                this.showAlert(result.message || 'Error sharing file', 'danger');
            }
        } catch (error) {
            this.showAlert('Error sharing file: ' + error.message, 'danger');
        }
    }
    
    async viewFileDetails(fileId) {
        // Get file info from server
        try {
            const response = await fetch(`/api/files/${fileId}`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });
            
            if (response.ok) {
                const file = await response.json();
                
                // Format file details
                const uploadDate = new Date(file.uploaded_at || file.uploadedAt);
                const fileSize = this.formatFileSize(file.size);
                const sharedWithCount = file.shared_with ? file.shared_with.length : (file.sharedWith ? file.sharedWith.length : 0);
                
                // Format shared users
                let sharedWithHtml = 'Not shared with anyone';
                if (file.shared_with || file.sharedWith) {
                    const sharedList = file.shared_with || file.sharedWith;
                    if (sharedList.length > 0) {
                        sharedWithHtml = '<ul>';
                        sharedList.forEach(share => {
                            const userName = share.username || share.user_name || 'Unknown';
                            const permission = share.permission || 'read';
                            sharedWithHtml += `<li>${userName} (${permission})</li>`;
                        });
                        sharedWithHtml += '</ul>';
                    }
                }
                
                const detailsHtml = `
                    <div class="row">
                        <div class="col-md-6">
                            <h6><i class="fas fa-file me-2"></i>File Information</h6>
                            <p><strong>Name:</strong> ${file.original_name || file.originalName || file.filename}</p>
                            <p><strong>Type:</strong> ${file.type || 'Unknown'}</p>
                            <p><strong>Size:</strong> ${fileSize}</p>
                            <p><strong>Uploaded:</strong> ${uploadDate.toLocaleString()}</p>
                            <p><strong>Encryption:</strong> <span class="badge bg-success">AES-256</span></p>
                        </div>
                        <div class="col-md-6">
                            <h6><i class="fas fa-share-alt me-2"></i>Sharing Information</h6>
                            <p><strong>Shared With:</strong> ${sharedWithCount} user(s)</p>
                            <p>${sharedWithHtml}</p>
                            <p><strong>Owner:</strong> ${file.owner_name || file.ownerName || 'Unknown'}</p>
                        </div>
                    </div>
                `;
                
                document.getElementById('file-details-content').innerHTML = detailsHtml;
                
                // Show the modal
                const modal = new bootstrap.Modal(document.getElementById('fileDetailsModal'));
                modal.show();
            } else {
                const error = await response.json();
                this.showAlert(error.message || 'Error loading file details', 'danger');
            }
        } catch (error) {
            this.showAlert('Error loading file details: ' + error.message, 'danger');
        }
    }
    
    async deleteFile(fileId) {
        if (!confirm('Are you sure you want to delete this file? This action cannot be undone.')) {
            return;
        }
        
        try {
            const response = await fetch(`/api/files/${fileId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });
            
            const result = await response.json();
            
            if (response.ok) {
                this.showAlert('File deleted successfully!', 'success');
                this.loadUserFiles(); // Refresh the file list
            } else {
                this.showAlert(result.message || 'Error deleting file', 'danger');
            }
        } catch (error) {
            this.showAlert('Error deleting file: ' + error.message, 'danger');
        }
    }
    
    logout() {
        this.token = null;
        this.currentUser = null;
        localStorage.removeItem('token');
        this.showUnauthedNav();
        this.showSection('login-section');
        this.showAlert('Logged out successfully', 'info');
    }
    
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    showAlert(message, type) {
        // Create alert element
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.role = 'alert';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        // Insert alert at the top of the container
        const container = document.querySelector('.container');
        container.insertBefore(alertDiv, container.firstChild);
        
        // Auto dismiss after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }
}

// Initialize the app when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.app = new SecureFileShareApp();
});
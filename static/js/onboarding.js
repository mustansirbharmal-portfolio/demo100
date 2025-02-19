// Function to show/hide sections based on completion
function updateSectionVisibility(status) {
    const sections = [
        { id: 'w9Section', completed: status.w9_completed },
        { id: 'idSection', completed: status.id_completed, requires: 'w9_completed' },
        { id: 'contractSection', completed: status.contract_completed, requires: 'id_completed' },
        { id: 'signSection', completed: status.sign_completed, requires: 'contract_completed' },
        { id: 'licenseSection', completed: status.license_completed, requires: 'sign_completed' },
        { id: 'loginSection', completed: status.login_completed, requires: 'license_completed' }
    ];

    sections.forEach((section, index) => {
        const element = document.getElementById(section.id);
        if (!element) return;

        // Show all sections but disable/enable based on previous completion
        element.style.display = 'block';
        
        if (index === 0) {
            // First section is always enabled
            enableSection(element);
        } else {
            const previousSection = sections[index - 1];
            const canEnable = status[previousSection.requires];
            
            if (canEnable) {
                enableSection(element);
            } else {
                disableSection(element);
            }
        }
    });
}

// Function to disable a section
function disableSection(element) {
    element.classList.add('disabled');
    element.style.opacity = '0.5';
    const buttons = element.querySelectorAll('button, input');
    buttons.forEach(button => {
        button.disabled = true;
    });
}

// Function to enable a section
function enableSection(element) {
    element.classList.remove('disabled');
    element.style.opacity = '1';
    const buttons = element.querySelectorAll('button, input');
    buttons.forEach(button => {
        button.disabled = false;
    });
}

// Function to update status icons
function updateStatusIcon(type, completed) {
    const icon = document.getElementById(`${type}StatusIcon`);
    const status = document.getElementById(`${type}Status`);
    
    if (!icon || !status) return;
    
    if (completed) {
        icon.classList.remove('bi-file-earmark-text', 'pending');
        icon.classList.add('bi-check-circle', 'completed');
        status.textContent = 'Completed';
        status.classList.remove('bg-primary');
        status.classList.add('bg-success');
    } else {
        icon.classList.remove('bi-check-circle', 'completed');
        icon.classList.add('bi-file-earmark-text', 'pending');
        status.textContent = 'Pending';
        status.classList.remove('bg-success');
        status.classList.add('bg-primary');
    }
}

// Function to update progress bar
function updateProgress() {
    const totalTasks = 6; // W-9, ID, Contract, Sign, License, Login
    let completedTasks = 0;
    
    ['w9', 'id', 'contract', 'sign', 'license', 'login'].forEach(type => {
        const status = document.getElementById(`${type}Status`);
        if (status && status.textContent === 'Completed') {
            completedTasks++;
        }
    });
    
    const progress = (completedTasks / totalTasks) * 100;
    const progressBar = document.getElementById('onboardingProgress');
    if (progressBar) {
        progressBar.style.width = progress + '%';
        progressBar.textContent = Math.round(progress) + '% Complete';
        progressBar.setAttribute('aria-valuenow', progress);
    }
}

// Function to refresh onboarding status
function refreshStatus() {
    fetch('/onboarding-status')
        .then(response => response.json())
        .then(status => {
            if (status.error) {
                console.error('Error:', status.error);
                return;
            }
            updateSectionVisibility(status);
            Object.keys(status).forEach(key => {
                if (key.endsWith('_completed')) {
                    const type = key.replace('_completed', '');
                    updateStatusIcon(type, status[key]);
                }
            });
            updateProgress();
        })
        .catch(error => console.error('Error:', error));
}

// Function to mark a task as complete
function markAsComplete(type) {
    fetch(`/mark-complete/${type}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            const errorDiv = document.getElementById(`${type}Error`);
            if (errorDiv) {
                errorDiv.textContent = data.error;
                errorDiv.style.display = 'block';
                setTimeout(() => {
                    errorDiv.style.display = 'none';
                }, 3000);
            }
            return;
        }
        if (data.success) {
            refreshStatus();
            const errorDiv = document.getElementById(`${type}Error`);
            if (errorDiv) {
                errorDiv.style.display = 'none';
            }
        }
    })
    .catch(error => {
        console.error('Error:', error);
        const errorDiv = document.getElementById(`${type}Error`);
        if (errorDiv) {
            errorDiv.textContent = 'An error occurred while updating status';
            errorDiv.style.display = 'block';
        }
    });
}

// Function to open contract form in a new window
function openContractForm() {
    const contractWindow = window.open('https://docs.google.com/forms/d/e/1FAIpQLSdXqRU099-J5OJQ9tns9XtxQcEi4uoILHyyZNxN-aFJIiG3mQ/viewform', '_blank');
    
    // Set up message listener for form completion
    window.addEventListener('message', async function(event) {
        if (event.data === 'contract_form_completed') {
            markAsComplete('contract');
        }
    });
}

// Handle W-9 file upload
document.getElementById('w9File').addEventListener('change', async function(e) {
    const errorDiv = document.getElementById('w9UploadError');
    errorDiv.style.display = 'none';
    
    if (!e.target.files.length) return;
    
    const file = e.target.files[0];
    if (!file.type.includes('pdf')) {
        errorDiv.textContent = 'Please upload a PDF file';
        errorDiv.style.display = 'block';
        return;
    }

    const formData = new FormData();
    formData.append('w9_file', file);

    try {
        const response = await fetch('/upload-w9', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        if (result.success) {
            markAsComplete('w9');
        } else {
            errorDiv.textContent = result.error || 'Error uploading W-9';
            errorDiv.style.display = 'block';
        }
    } catch (error) {
        console.error('Error:', error);
        errorDiv.textContent = 'An error occurred while uploading the W-9';
        errorDiv.style.display = 'block';
    }
});

// Handle ID file upload
document.getElementById('idFile').addEventListener('change', async function(e) {
    const errorDiv = document.getElementById('idUploadError');
    errorDiv.style.display = 'none';
    
    if (!e.target.files.length) return;
    
    const file = e.target.files[0];
    if (!file.type.includes('pdf')) {
        errorDiv.textContent = 'Please upload a PDF file';
        errorDiv.style.display = 'block';
        return;
    }

    const formData = new FormData();
    formData.append('id_file', file);

    try {
        const response = await fetch('/upload-id', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        if (result.success) {
            markAsComplete('id');
        } else {
            errorDiv.textContent = result.error || 'Error uploading ID';
            errorDiv.style.display = 'block';
        }
    } catch (error) {
        console.error('Error:', error);
        errorDiv.textContent = 'An error occurred while uploading the ID';
        errorDiv.style.display = 'block';
    }
});

// Initialize status on page load
document.addEventListener('DOMContentLoaded', function() {
    refreshStatus();
});
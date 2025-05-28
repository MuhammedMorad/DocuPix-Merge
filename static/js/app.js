document.getElementById('togglePassword').addEventListener('click', function() {
    const passwordInput = document.getElementById('passwordInput');
    const showIcon = document.getElementById('showIcon');
    const hideIcon = document.getElementById('hideIcon');
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        showIcon.classList.add('d-none');
        hideIcon.classList.remove('d-none');
    } else {
        passwordInput.type = 'password';
        hideIcon.classList.add('d-none');
        showIcon.classList.remove('d-none');
    }
});


function handleDropZoneEvents() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');

    // Prevent default drag behaviors
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
    });

    // Highlight drop zone when item is dragged over it
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, highlight, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, unhighlight, false);
    });

    // Handle dropped files
    dropZone.addEventListener('drop', handleDrop, false);

    function preventDefaults (e) {
        e.preventDefault();
        e.stopPropagation();
    }

    function highlight(e) {
        dropZone.style.borderColor = '#0056b3';
        dropZone.style.backgroundColor = '#e9ecef';
    }

    function unhighlight(e) {
        dropZone.style.borderColor = '#007bff';
        dropZone.style.backgroundColor = 'transparent';
    }

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        fileInput.files = files;
        updateFileList(files);
    }
}

function updateFileList(files) {
    const fileList = document.getElementById('fileList');
    fileList.innerHTML = '';
    
    if (files.length > 0) {
        const list = document.createElement('div');
        for (const file of files) {
            const item = document.createElement('div');
            item.textContent = file.name;
            list.appendChild(item);
        }
        fileList.appendChild(list);
    } else {
        fileList.textContent = 'No files selected yet';
    }
}

// Initialize drop zone when page loads
document.addEventListener('DOMContentLoaded', handleDropZoneEvents);

document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('fileInput');
    const fileList = document.getElementById('fileList');
    const uploadBtn = document.getElementById('uploadBtn');

    fileInput.addEventListener('change', () => {
        const files = fileInput.files;
        if (files.length > 0) {
            const fileNames = Array.from(files).map(file => file.name).join(', ');
            fileList.innerHTML = `<strong>Selected Files:</strong><br>${fileNames}`;
            uploadBtn.classList.remove('hidden');
        } else {
            fileList.textContent = 'No files selected';
            uploadBtn.classList.add('hidden');
        }
    });

    // Drag & drop handlers
    const dropZone = document.getElementById('dropZone');
    
    ['dragover', 'dragenter'].forEach(event => {
        dropZone.addEventListener(event, (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(event => {
        dropZone.addEventListener(event, (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
        });
    });

    dropZone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        fileInput.files = files;
        fileInput.dispatchEvent(new Event('change'));
    });
});

function uploadFiles() {
    document.getElementById('uploadForm').submit();
}

document.addEventListener('DOMContentLoaded', function() {
    const downloadBtn = document.getElementById('downloadSection');
    if(downloadBtn) {
        setTimeout(() => {
            downloadBtn.style.opacity = '0';
            setTimeout(() => {
                downloadBtn.remove();
            }, 1000);
        }, 60000); // 60 ثانية
    }
});
// Settings Page JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // --- Theme Logic ---
    const themeCards = document.querySelectorAll('.theme-card');
    const rootStyle = document.documentElement.style;

    // Define theme colors matching CSS variables
    const themes = {
        dark: { bg: '#1a1a2e', sidebar: '#16213e', mainText: '#e0e0e0', accent: '#4a90e2' },
        light: { bg: '#f0f2f5', sidebar: '#ffffff', mainText: '#333333', accent: '#0084ff' },
        blue: { bg: '#0f172a', sidebar: '#1e293b', mainText: '#e2e8f0', accent: '#38bdf8' },
        green: { bg: '#064e3b', sidebar: '#065f46', mainText: '#d1fae5', accent: '#34d399' },
        purple: { bg: '#2e1065', sidebar: '#4c1d95', mainText: '#ede9fe', accent: '#c084fc' }
    };

    function applyTheme(themeName) {
        const theme = themes[themeName];
        if (!theme) return;

        // Apply CSS variables to root
        rootStyle.setProperty('--bg-color', theme.bg);
        rootStyle.setProperty('--sidebar-bg', theme.sidebar);
        rootStyle.setProperty('--main-text', theme.mainText);
        rootStyle.setProperty('--accent-color', theme.accent);
        
        // Save to localStorage for persistence across pages
        localStorage.setItem('selectedTheme', themeName);

        // Update visual selection state
        themeCards.forEach(card => {
            card.classList.remove('active');
            if (card.getAttribute('data-theme') === themeName) {
                card.classList.add('active');
            }
        });
    }

    // Add click listeners to theme cards
    themeCards.forEach(card => {
        card.addEventListener('click', function(e) {
            e.preventDefault();
            const selectedTheme = this.getAttribute('data-theme');
            applyTheme(selectedTheme);
            
            // Also update hidden input for form submission
            let themeInput = document.getElementById('selected-theme-input');
            if (!themeInput) {
                themeInput = document.createElement('input');
                themeInput.type = 'hidden';
                themeInput.id = 'selected-theme-input';
                themeInput.name = 'active_theme';
                document.querySelector('form').appendChild(themeInput);
            }
            themeInput.value = selectedTheme;
        });
    });

    // Load saved theme on startup
    const savedTheme = localStorage.getItem('selectedTheme') || 'dark';
    applyTheme(savedTheme);
    
    // Profile picture upload preview
    const profilePicInput = document.getElementById('profile-pic-input');
    const profilePreview = document.getElementById('profile-preview');
    
    if (profilePicInput && profilePreview) {
        profilePicInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function(event) {
                    if (profilePreview.tagName === 'IMG') {
                        profilePreview.src = event.target.result;
                    } else {
                        // Replace div with img
                        const img = document.createElement('img');
                        img.src = event.target.result;
                        img.alt = 'Profile picture';
                        img.id = 'profile-preview';
                        profilePreview.parentNode.replaceChild(img, profilePreview);
                    }
                };
                reader.readAsDataURL(file);
            }
        });
    }
    
    // Remove profile picture button
    const removePicBtn = document.getElementById('remove-pic-btn');
    if (removePicBtn) {
        removePicBtn.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Create a form to submit the removal
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/settings/remove-profile-pic';
            
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'remove_pic';
            input.value = 'true';
            
            form.appendChild(input);
            document.body.appendChild(form);
            form.submit();
        });
    }
    
    // Auto-hide alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'opacity 0.5s';
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 500);
        }, 5000);
    });
});

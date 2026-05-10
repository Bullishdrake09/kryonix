// Settings Page JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Theme selection functionality
    const themeCards = document.querySelectorAll('.theme-card');
    const customThemeCard = document.getElementById('custom-theme-card');
    
    themeCards.forEach(card => {
        card.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all cards
            themeCards.forEach(c => c.classList.remove('active'));
            
            // Add active class to clicked card
            this.classList.add('active');
            
            // Get the selected theme
            const selectedTheme = this.getAttribute('data-theme');
            
            // Store in a hidden input or data attribute for form submission
            let themeInput = document.getElementById('selected-theme-input');
            if (!themeInput) {
                themeInput = document.createElement('input');
                themeInput.type = 'hidden';
                themeInput.id = 'selected-theme-input';
                themeInput.name = 'active_theme';
                document.querySelector('form').appendChild(themeInput);
            }
            themeInput.value = selectedTheme;
            
            // Visual feedback - update custom theme card if custom is selected
            if (selectedTheme === 'custom' && customThemeCard) {
                const themeDesc = customThemeCard.querySelector('.theme-desc');
                if (themeDesc) {
                    themeDesc.innerHTML = '<span style="color:var(--success);"><i class="fas fa-check-circle"></i> Selected</span>';
                }
            }
        });
    });
    
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

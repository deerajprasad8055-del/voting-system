/**
 * SecureVote Client-side Scripts
 * Handles mobile navigation, flash toast dismissal, candidate selection,
 * vote confirmation modal, password strength analysis, and cryptographic payload copying.
 */

document.addEventListener('DOMContentLoaded', () => {
    // -------------------------------------------------------------
    // 1. Mobile Menu Toggle
    // -------------------------------------------------------------
    const mobileToggle = document.querySelector('.mobile-toggle');
    const navMenu = document.querySelector('.nav-menu');
    if (mobileToggle && navMenu) {
        mobileToggle.addEventListener('click', () => {
            navMenu.classList.toggle('open');
        });
    }

    // -------------------------------------------------------------
    // 2. Flash Toast Auto-Dismissal
    // -------------------------------------------------------------
    const toasts = document.querySelectorAll('.toast');
    toasts.forEach(toast => {
        const closeBtn = toast.querySelector('.toast-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                toast.style.opacity = '0';
                toast.style.transform = 'translateX(100%)';
                setTimeout(() => toast.remove(), 300);
            });
        }
        // Auto-dismiss after 6 seconds
        setTimeout(() => {
            if (toast && toast.parentElement) {
                toast.style.opacity = '0';
                toast.style.transform = 'translateX(100%)';
                setTimeout(() => toast.remove(), 300);
            }
        }, 6000);
    });

    // -------------------------------------------------------------
    // 3. Password Strength Meter (Register Page)
    // -------------------------------------------------------------
    const passwordInput = document.getElementById('password');
    const strengthBar = document.getElementById('strength-bar');
    const strengthText = document.getElementById('strength-text');

    if (passwordInput && strengthBar && strengthText) {
        passwordInput.addEventListener('input', () => {
            const val = passwordInput.value;
            let score = 0;
            if (val.length >= 8) score++;
            if (/[A-Z]/.test(val)) score++;
            if (/[a-z]/.test(val)) score++;
            if (/[0-9]/.test(val)) score++;
            if (/[^A-Za-z0-9]/.test(val)) score++;

            strengthBar.className = 'strength-bar';
            if (val.length === 0) {
                strengthBar.style.width = '0%';
                strengthText.textContent = '';
            } else if (score <= 2) {
                strengthBar.classList.add('strength-weak');
                strengthText.textContent = 'Weak (Needs length, upper/lower, and numbers)';
                strengthText.style.color = 'var(--danger)';
            } else if (score <= 4) {
                strengthBar.classList.add('strength-medium');
                strengthText.textContent = 'Medium (Add special symbols for high security)';
                strengthText.style.color = 'var(--warning)';
            } else {
                strengthBar.classList.add('strength-strong');
                strengthText.textContent = 'Strong (Cryptographically secure password)';
                strengthText.style.color = 'var(--success)';
            }
        });
    }

    // -------------------------------------------------------------
    // 4. Candidate Card Selection (Voting Page)
    // -------------------------------------------------------------
    const candidateCards = document.querySelectorAll('.candidate-card');
    const voteSubmitBtn = document.getElementById('btn-vote-submit');

    candidateCards.forEach(card => {
        card.addEventListener('click', () => {
            candidateCards.forEach(c => c.classList.remove('selected'));
            card.classList.add('selected');
            const radio = card.querySelector('input[type="radio"]');
            if (radio) {
                radio.checked = true;
            }
            if (voteSubmitBtn) {
                voteSubmitBtn.disabled = false;
            }
        });
    });

    // -------------------------------------------------------------
    // 5. Vote Confirmation Modal
    // -------------------------------------------------------------
    const voteForm = document.getElementById('vote-form');
    const voteModal = document.getElementById('vote-modal');
    const confirmVoteBtn = document.getElementById('btn-confirm-vote');
    const cancelVoteBtn = document.getElementById('btn-cancel-vote');

    if (voteSubmitBtn && voteModal && voteForm) {
        voteSubmitBtn.addEventListener('click', (e) => {
            const selected = document.querySelector('input[name="candidate_id"]:checked');
            if (!selected) {
                alert("Please select a candidate before proceeding.");
                return;
            }
            const candName = selected.closest('.candidate-card').querySelector('.candidate-name').textContent;
            const modalCandName = document.getElementById('modal-candidate-name');
            if (modalCandName) modalCandName.textContent = candName;
            voteModal.classList.add('active');
        });
    }

    if (cancelVoteBtn && voteModal) {
        cancelVoteBtn.addEventListener('click', () => {
            voteModal.classList.remove('active');
        });
    }

    if (confirmVoteBtn && voteForm) {
        confirmVoteBtn.addEventListener('click', () => {
            confirmVoteBtn.disabled = true;
            confirmVoteBtn.innerHTML = `
                <svg style="animation: spin 1s linear infinite; width:18px; height:18px; margin-right:6px;" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                    <circle cx="12" cy="12" r="10" stroke-width="4" stroke="rgba(255,255,255,0.2)"></circle>
                    <path d="M4 12a8 8 0 018-8v8H4z" fill="currentColor"></path>
                </svg> Encrypting & Sealing Vote...
            `;
            voteForm.submit();
        });
    }

    // -------------------------------------------------------------
    // 6. Copy to Clipboard
    // -------------------------------------------------------------
    window.copyToClipboard = function(text, btnElement) {
        navigator.clipboard.writeText(text).then(() => {
            const originalText = btnElement.innerText;
            btnElement.innerText = "Copied!";
            btnElement.style.background = "var(--success)";
            btnElement.style.color = "#fff";
            setTimeout(() => {
                btnElement.innerText = originalText;
                btnElement.style.background = "";
                btnElement.style.color = "";
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy: ', err);
        });
    };

    // -------------------------------------------------------------
    // 7. Demo Credential Autofill Helper
    // -------------------------------------------------------------
    window.fillLogin = function(email, password) {
        const emailInput = document.getElementById('email');
        const passwordInput = document.getElementById('password');
        if (emailInput && passwordInput) {
            emailInput.value = email;
            passwordInput.value = password;
        }
    };

    // -------------------------------------------------------------
    // 8. Lightweight Confetti Particle Generator (Receipt Page)
    // -------------------------------------------------------------
    const confettiContainer = document.getElementById('confetti-canvas');
    if (confettiContainer) {
        launchConfetti(confettiContainer);
    }
});

function launchConfetti(canvas) {
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const pieces = [];
    const colors = ['#6366f1', '#06b6d4', '#10b981', '#f59e0b', '#ec4899', '#ffffff'];

    for (let i = 0; i < 90; i++) {
        pieces.push({
            x: Math.random() * canvas.width,
            y: Math.random() * canvas.height - canvas.height,
            size: Math.random() * 8 + 4,
            speed: Math.random() * 3 + 2,
            color: colors[Math.floor(Math.random() * colors.length)],
            rotation: Math.random() * 360,
            rotationSpeed: (Math.random() - 0.5) * 4
        });
    }

    let frame = 0;
    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        pieces.forEach(p => {
            ctx.save();
            ctx.translate(p.x, p.y);
            ctx.rotate((p.rotation * Math.PI) / 180);
            ctx.fillStyle = p.color;
            ctx.fillRect(-p.size / 2, -p.size / 2, p.size, p.size);
            ctx.restore();

            p.y += p.speed;
            p.rotation += p.rotationSpeed;

            if (p.y > canvas.height) {
                p.y = -20;
                p.x = Math.random() * canvas.width;
            }
        });

        frame++;
        if (frame < 180) {
            requestAnimationFrame(animate);
        } else {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
        }
    }
    animate();
}

// Add spinning CSS keyframe
const styleSheet = document.createElement("style");
styleSheet.innerText = `
@keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}
`;
document.head.appendChild(styleSheet);


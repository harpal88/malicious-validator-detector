// Main JavaScript for Solana Validator Detector

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips if Bootstrap is available
    if (typeof bootstrap !== 'undefined') {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function(tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }

    // Format public keys to be more readable
    const formatPubkeys = () => {
        const pubkeyElements = document.querySelectorAll('.pubkey-full');
        pubkeyElements.forEach(element => {
            const pubkey = element.textContent;
            if (pubkey && pubkey.length > 15) {
                element.innerHTML = `${pubkey.substring(0, 10)}...${pubkey.substring(pubkey.length - 5)}`;
                element.setAttribute('title', pubkey);
                element.classList.add('pubkey-tooltip');
            }
        });
    };

    // Call formatting function
    formatPubkeys();

    // Add copy to clipboard functionality
    const copyButtons = document.querySelectorAll('.copy-btn');
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const textToCopy = this.getAttribute('data-copy');
            navigator.clipboard.writeText(textToCopy).then(() => {
                // Show success feedback
                const originalText = this.innerHTML;
                this.innerHTML = 'Copied!';
                setTimeout(() => {
                    this.innerHTML = originalText;
                }, 2000);
            });
        });
    });

    // Add active class to current nav item
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.navbar-nav .nav-link');
    navLinks.forEach(link => {
        const linkPath = link.getAttribute('href');
        if (currentPath === linkPath ||
            (linkPath !== '/' && currentPath.startsWith(linkPath))) {
            link.classList.add('active');
        }
    });

    // Animate score circles
    const animateScoreCircles = () => {
        const scoreCircles = document.querySelectorAll('.risk-score-circle, .performance-score-circle');
        scoreCircles.forEach(circle => {
            const score = parseInt(circle.textContent.trim());
            if (!isNaN(score)) {
                let counter = 0;
                const target = score;
                const duration = 1500; // ms
                const frameRate = 1000 / 60; // 60fps
                const totalFrames = Math.round(duration / frameRate);
                const increment = target / totalFrames;

                const timer = setInterval(() => {
                    counter += increment;
                    if (counter >= target) {
                        clearInterval(timer);
                        circle.textContent = target;
                    } else {
                        circle.textContent = Math.round(counter);
                    }
                }, frameRate);
            }
        });
    };

    // Animate elements when they come into view
    const animateOnScroll = () => {
        const elements = document.querySelectorAll('.card, .stat-card');
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate__animated', 'animate__fadeInUp');
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1 });

        elements.forEach(element => {
            observer.observe(element);
        });
    };

    // Add animation library if not already included
    if (!document.querySelector('link[href*="animate.css"]')) {
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = 'https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css';
        document.head.appendChild(link);

        // Wait for animation library to load
        link.onload = () => {
            animateOnScroll();
            animateScoreCircles();
        };
    } else {
        animateOnScroll();
        animateScoreCircles();
    }

    // Add smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);

            if (targetElement) {
                window.scrollTo({
                    top: targetElement.offsetTop - 80, // Offset for fixed header
                    behavior: 'smooth'
                });
            }
        });
    });
});

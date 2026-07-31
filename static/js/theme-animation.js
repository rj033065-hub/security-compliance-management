/**
 * Security Command Center - Unified Light Theme Animation System & Utilities
 * Theme: Light Background (#F7F8FA) with Deep Cobalt Blue Accents (#2454E0) & Dark Navy Text (#10162B)
 */

(function () {
    "use strict";

    // ── Reduced Motion Preference Check ──────────────────────────────
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // ══════════════════════════════════════════════════════════════════
    // 1. MESH BACKGROUND CANVAS (Light Theme: Dark Navy dots, blue lines, red/orange cursor flash)
    // ══════════════════════════════════════════════════════════════════
    class MeshBackground {
        constructor(canvasId, options = {}) {
            this.canvas = document.getElementById(canvasId);
            if (!this.canvas) return;
            this.ctx = this.canvas.getContext("2d");

            this.nodeCount = options.nodeCount || parseInt(this.canvas.getAttribute("data-nodes") || "40", 10);
            this.maxDistance = options.maxDistance || 140;
            this.mouseRadius = options.mouseRadius || 180;

            // Light theme colors
            this.nodeColor = options.nodeColor || "rgba(16, 22, 43, 0.65)";        // Dark navy dots
            this.lineColor = options.lineColor || "rgba(36, 84, 224, 0.22)";        // Faint cobalt blue lines
            this.cursorLineColor = "rgba(227, 115, 24, 0.85)";                      // Orange/red contrast flash near cursor
            this.speedMult = options.speed || 0.4;

            this.nodes = [];
            this.mouse = { x: null, y: null, active: false };
            this.animFrameId = null;
            this.isPaused = false;

            this.init();
        }

        init() {
            if (prefersReducedMotion) return;

            this.resize();
            this.createNodes();

            window.addEventListener("resize", () => this.resize());
            
            // Mouse interactions
            window.addEventListener("mousemove", (e) => {
                const rect = this.canvas.getBoundingClientRect();
                this.mouse.x = e.clientX - rect.left;
                this.mouse.y = e.clientY - rect.top;
                this.mouse.active = true;
            });

            window.addEventListener("mouseleave", () => {
                this.mouse.active = false;
            });

            // Pause when tab is not visible to conserve CPU
            document.addEventListener("visibilitychange", () => {
                if (document.hidden) {
                    this.pause();
                } else {
                    this.resume();
                }
            });

            this.animate();
        }

        resize() {
            if (!this.canvas) return;
            const parent = this.canvas.parentElement || document.body;
            this.width = this.canvas.width = parent.clientWidth || window.innerWidth;
            this.height = this.canvas.height = parent.clientHeight || window.innerHeight;
        }

        createNodes() {
            this.nodes = [];
            for (let i = 0; i < this.nodeCount; i++) {
                this.nodes.push({
                    x: Math.random() * this.width,
                    y: Math.random() * this.height,
                    vx: (Math.random() - 0.5) * this.speedMult,
                    vy: (Math.random() - 0.5) * this.speedMult,
                    radius: Math.random() * 2 + 1.2
                });
            }
        }

        animate() {
            if (this.isPaused) return;

            this.ctx.clearRect(0, 0, this.width, this.height);

            // Update & Draw Nodes
            for (let i = 0; i < this.nodes.length; i++) {
                const node = this.nodes[i];

                // Move nodes
                node.x += node.vx;
                node.y += node.vy;

                // Bounce off edges
                if (node.x < 0 || node.x > this.width) node.vx *= -1;
                if (node.y < 0 || node.y > this.height) node.vy *= -1;

                let isNearCursor = false;

                // Mouse attraction/repulsion
                if (this.mouse.active) {
                    const dx = this.mouse.x - node.x;
                    const dy = this.mouse.y - node.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < this.mouseRadius) {
                        isNearCursor = true;
                        const force = (this.mouseRadius - dist) / this.mouseRadius;
                        node.x -= (dx / dist) * force * 1.5;
                        node.y -= (dy / dist) * force * 1.5;
                    }
                }

                // Draw Node Point
                this.ctx.beginPath();
                this.ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
                this.ctx.fillStyle = isNearCursor ? "#C1443A" : this.nodeColor;
                this.ctx.fill();

                // Connect nearby nodes
                for (let j = i + 1; j < this.nodes.length; j++) {
                    const node2 = this.nodes[j];
                    const dx = node.x - node2.x;
                    const dy = node.y - node2.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < this.maxDistance) {
                        const alpha = (1 - dist / this.maxDistance) * 0.45;
                        this.ctx.beginPath();
                        this.ctx.moveTo(node.x, node.y);
                        this.ctx.lineTo(node2.x, node2.y);
                        
                        if (isNearCursor) {
                            this.ctx.strokeStyle = `rgba(227, 115, 24, ${alpha + 0.3})`;
                            this.ctx.lineWidth = 1.2;
                        } else {
                            this.ctx.strokeStyle = `rgba(36, 84, 224, ${alpha})`;
                            this.ctx.lineWidth = 0.8;
                        }
                        this.ctx.stroke();
                    }
                }
            }

            this.animFrameId = requestAnimationFrame(() => this.animate());
        }

        pause() {
            this.isPaused = true;
            if (this.animFrameId) cancelAnimationFrame(this.animFrameId);
        }

        resume() {
            if (this.isPaused) {
                this.isPaused = false;
                this.animate();
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // 2. SCROLL REVEAL (IntersectionObserver with stagger support)
    // ══════════════════════════════════════════════════════════════════
    function initScrollReveal() {
        const revealElements = document.querySelectorAll(".scroll-reveal, .glass-card, .kpi-card, .table-responsive");
        if (!revealElements.length) return;

        if (prefersReducedMotion) {
            revealElements.forEach(el => el.classList.add("scroll-in"));
            return;
        }

        const observer = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    const el = entry.target;
                    const stagger = parseInt(el.getAttribute("data-stagger") || "0", 10);
                    
                    setTimeout(() => {
                        el.classList.add("scroll-in");
                    }, stagger);

                    observer.unobserve(el);
                }
            });
        }, { threshold: 0.12 });

        revealElements.forEach((el) => {
            if (!el.hasAttribute("data-stagger")) {
                const parent = el.closest(".row");
                if (parent) {
                    const children = Array.from(parent.children);
                    const childIdx = children.indexOf(el.parentElement || el);
                    if (childIdx !== -1) {
                        el.setAttribute("data-stagger", (childIdx * 70).toString());
                    }
                }
            }
            observer.observe(el);
        });
    }

    // ══════════════════════════════════════════════════════════════════
    // 3. TILT HOVER EFFECT (3D Card Tilt on Mouse Position)
    // ══════════════════════════════════════════════════════════════════
    function initTiltHover() {
        if (prefersReducedMotion) return;

        const tiltCards = document.querySelectorAll(".tilt-card, .kpi-card, .glass-card");
        tiltCards.forEach(card => {
            card.addEventListener("mousemove", (e) => {
                const rect = card.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;

                const centerX = rect.width / 2;
                const centerY = rect.height / 2;

                const rotateX = -((y - centerY) / centerY) * 6; // Max 6deg tilt
                const rotateY = ((x - centerX) / centerX) * 6;

                card.style.transform = `perspective(1000px) rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) translateZ(4px)`;
                card.style.transition = "transform 0.1s ease-out";
            });

            card.addEventListener("mouseleave", () => {
                card.style.transform = "perspective(1000px) rotateX(0deg) rotateY(0deg) translateZ(0px)";
                card.style.transition = "transform 0.4s ease-in-out";
            });
        });
    }

    // ══════════════════════════════════════════════════════════════════
    // 4. COUNT-UP UTILITY & LIVE FLICKER (Real-time KPI feel)
    // ══════════════════════════════════════════════════════════════════
    function initCountUp() {
        const countElems = document.querySelectorAll("[data-count-up], h3.fw-extrabold");

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const el = entry.target;
                    const text = el.innerText.trim();
                    const match = text.match(/([^\d]*)([\d,.]+)([^\d]*)/);

                    if (match) {
                        const prefix = match[1] || "";
                        const rawNum = parseFloat(match[2].replace(/,/g, ""));
                        const suffix = match[3] || "";
                        const duration = parseInt(el.getAttribute("data-duration") || "1200", 10);

                        if (!isNaN(rawNum) && rawNum > 0) {
                            animateNumber(el, 0, rawNum, prefix, suffix, duration, () => {
                                if (el.hasAttribute("data-flicker") || el.innerText.includes("%") || el.closest(".kpi-card")) {
                                    startLiveFlicker(el, rawNum, prefix, suffix);
                                }
                            });
                        }
                    }
                    observer.unobserve(el);
                }
            });
        }, { threshold: 0.2 });

        countElems.forEach(el => observer.observe(el));
    }

    function animateNumber(el, start, end, prefix, suffix, duration, callback) {
        if (prefersReducedMotion) {
            el.innerText = `${prefix}${end}${suffix}`;
            if (callback) callback();
            return;
        }

        const startTime = performance.now();
        const isFloat = end.toString().includes(".");

        function update(now) {
            const elapsed = now - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const easeProgress = 1 - Math.pow(1 - progress, 3);
            const current = start + (end - start) * easeProgress;

            el.innerText = `${prefix}${isFloat ? current.toFixed(1) : Math.round(current)}${suffix}`;

            if (progress < 1) {
                requestAnimationFrame(update);
            } else {
                el.innerText = `${prefix}${end}${suffix}`;
                if (callback) callback();
            }
        }

        requestAnimationFrame(update);
    }

    function startLiveFlicker(el, baseVal, prefix, suffix) {
        setInterval(() => {
            if (document.hidden) return;
            if (Math.random() > 0.4) return;

            const delta = Math.random() > 0.5 ? 1 : -1;
            const flickerVal = Math.max(0, baseVal + delta);

            el.style.transition = "color 0.2s ease, transform 0.2s ease";
            el.style.color = "var(--accent)";
            el.innerText = `${prefix}${flickerVal}${suffix}`;

            setTimeout(() => {
                el.style.color = "";
                el.innerText = `${prefix}${baseVal}${suffix}`;
            }, 800);
        }, 4500);
    }

    // ══════════════════════════════════════════════════════════════════
    // 5. TYPEWRITER UTILITY
    // ══════════════════════════════════════════════════════════════════
    function initTypewriter() {
        const typewriterElems = document.querySelectorAll("[data-typewriter]");

        typewriterElems.forEach(el => {
            const rawPhrases = el.getAttribute("data-typewriter-phrases");
            let phrases = [el.innerText.trim()];
            if (rawPhrases) {
                try { phrases = JSON.parse(rawPhrases); } catch (e) {}
            }

            const speed = parseInt(el.getAttribute("data-speed") || "45", 10);
            const delay = parseInt(el.getAttribute("data-delay") || "2200", 10);

            el.innerHTML = '<span class="typewriter-text"></span><span class="typewriter-caret">|</span>';
            const textSpan = el.querySelector(".typewriter-text");

            let phraseIdx = 0;
            let charIdx = 0;
            let isDeleting = false;

            function typeStep() {
                if (document.hidden) {
                    setTimeout(typeStep, 500);
                    return;
                }

                const currentPhrase = phrases[phraseIdx];

                if (isDeleting) {
                    charIdx--;
                    textSpan.innerText = currentPhrase.substring(0, charIdx);
                } else {
                    charIdx++;
                    textSpan.innerText = currentPhrase.substring(0, charIdx);
                }

                let currentSpeed = isDeleting ? speed / 2 : speed;

                if (!isDeleting && charIdx === currentPhrase.length) {
                    if (phrases.length === 1) return;
                    currentSpeed = delay;
                    isDeleting = true;
                } else if (isDeleting && charIdx === 0) {
                    isDeleting = false;
                    phraseIdx = (phraseIdx + 1) % phrases.length;
                    currentSpeed = 400;
                }

                setTimeout(typeStep, currentSpeed);
            }

            typeStep();
        });
    }

    // ══════════════════════════════════════════════════════════════════
    // 6. SIDEBAR NAV SLIDING ACTIVE INDICATOR
    // ══════════════════════════════════════════════════════════════════
    function initSidebarNavSlider() {
        const sidebar = document.getElementById("sidebar");
        if (!sidebar) return;

        const navList = sidebar.querySelector("ul.components");
        if (!navList) return;

        const activeLi = navList.querySelector("li.active");
        if (!activeLi) return;

        let indicator = sidebar.querySelector(".sidebar-active-indicator");
        if (!indicator) {
            indicator = document.createElement("div");
            indicator.className = "sidebar-active-indicator";
            sidebar.appendChild(indicator);
        }

        function updateIndicatorPos(targetLi) {
            const rect = targetLi.getBoundingClientRect();
            const sidebarRect = sidebar.getBoundingClientRect();

            indicator.style.top = `${rect.top - sidebarRect.top + sidebar.scrollTop}px`;
            indicator.style.height = `${rect.height}px`;
        }

        updateIndicatorPos(activeLi);
        sidebar.addEventListener("scroll", () => updateIndicatorPos(activeLi));
        window.addEventListener("resize", () => updateIndicatorPos(activeLi));
    }

    // ══════════════════════════════════════════════════════════════════
    // 7. INPUT FIELD VALIDATION & SUBMIT SPINNER ANIMATIONS
    // ══════════════════════════════════════════════════════════════════
    function initFormAnimations() {
        const forms = document.querySelectorAll("form");

        forms.forEach(form => {
            const inputs = form.querySelectorAll(".form-control, .form-select");
            inputs.forEach(input => {
                const group = input.closest(".input-group");
                if (group) {
                    if (!group.querySelector(".input-valid-icon")) {
                        const checkSpan = document.createElement("span");
                        checkSpan.className = "input-valid-icon";
                        checkSpan.innerHTML = '<i class="fas fa-circle-check text-success"></i>';
                        group.appendChild(checkSpan);
                    }
                }

                input.addEventListener("input", function () {
                    if (this.checkValidity() && this.value.trim().length > 2) {
                        this.classList.remove("is-invalid");
                        this.classList.add("is-valid");
                        if (group) group.classList.add("has-valid-icon");
                    } else {
                        this.classList.remove("is-valid");
                        if (group) group.classList.remove("has-valid-icon");
                    }
                });

                input.addEventListener("invalid", function () {
                    this.classList.add("is-invalid");
                    this.classList.add("shake-error");
                    setTimeout(() => this.classList.remove("shake-error"), 600);
                });
            });

            form.addEventListener("submit", function () {
                const btn = form.querySelector("button[type='submit']");
                if (!btn || btn.classList.contains("btn-loading")) return;

                if (!form.checkValidity()) return;

                btn.classList.add("btn-loading");
                btn.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status"></span> Authentic & Processing...`;
            });
        });
    }

    // ══════════════════════════════════════════════════════════════════
    // 8. 5x5 RISK HEATMAP STAGGER & HOVER ENHANCEMENTS
    // ══════════════════════════════════════════════════════════════════
    function initRiskHeatmap() {
        const heatmapTable = document.querySelector(".heatmap-table");
        if (!heatmapTable) return;

        const cells = heatmapTable.querySelectorAll(".heatmap-cell");
        cells.forEach((cell, idx) => {
            if (!prefersReducedMotion) {
                cell.style.opacity = "0";
                cell.style.transform = "scale(0.85)";

                setTimeout(() => {
                    cell.style.transition = "opacity 0.4s ease, transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275)";
                    cell.style.opacity = "1";
                    cell.style.transform = "scale(1)";
                }, 100 + idx * 45);
            }

            cell.addEventListener("mouseenter", function () {
                this.style.transform = "scale(1.12)";
                this.style.boxShadow = "0 8px 20px rgba(16, 22, 43, 0.18)";
            });

            cell.addEventListener("mouseleave", function () {
                this.style.transform = "scale(1)";
                this.style.boxShadow = "none";
            });
        });
    }

    // ══════════════════════════════════════════════════════════════════
    // DOM READY INITIALIZATION
    // ══════════════════════════════════════════════════════════════════
    document.addEventListener("DOMContentLoaded", () => {
        if (document.getElementById("meshCanvas")) {
            new MeshBackground("meshCanvas", { nodeCount: 65, maxDistance: 130 });
        }

        if (document.getElementById("dashHeaderMesh")) {
            new MeshBackground("dashHeaderMesh", { nodeCount: 25, maxDistance: 100, speed: 0.25 });
        }

        initScrollReveal();
        initTiltHover();
        initCountUp();
        initTypewriter();
        initSidebarNavSlider();
        initFormAnimations();
        initRiskHeatmap();
    });

})();

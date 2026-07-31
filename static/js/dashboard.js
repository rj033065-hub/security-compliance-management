// Security Command Center - Chart.js Visualizations v4.0
// Warm Graphite Palette (#161310) with Burnt Orange (#E37318) and IBM Plex Typography

document.addEventListener("DOMContentLoaded", function () {
    if (typeof Chart === 'undefined') return;

    // Shared Chart.js Font & Style Defaults
    Chart.defaults.font.family = "'IBM Plex Sans', sans-serif";
    Chart.defaults.color = '#A89985';
    Chart.defaults.borderColor = '#3B3227';

    // 1. Compliance Trend Chart (Line Chart)
    const trendCtx = document.getElementById('trendChart');
    if (trendCtx) {
        const ctx = trendCtx.getContext('2d');
        const gradient = ctx.createLinearGradient(0, 0, 0, 260);
        gradient.addColorStop(0, 'rgba(227, 115, 24, 0.4)');
        gradient.addColorStop(1, 'rgba(227, 115, 24, 0.0)');

        new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: ['Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
                datasets: [{
                    label: 'Overall Compliance %',
                    data: [68, 72, 79, 81, 85, 91],
                    borderColor: '#E37318',
                    backgroundColor: gradient,
                    fill: true,
                    tension: 0.38,
                    borderWidth: 3,
                    pointBackgroundColor: '#E37318',
                    pointBorderColor: '#EDE6D9',
                    pointBorderWidth: 2,
                    pointRadius: 5,
                    pointHoverRadius: 7
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    duration: 1200,
                    easing: 'easeOutQuart'
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#221C16',
                        borderColor: '#3B3227',
                        borderWidth: 1,
                        titleColor: '#EDE6D9',
                        bodyColor: '#A89985',
                        titleFont: { family: "'IBM Plex Mono', monospace", weight: 'bold' },
                        padding: 12,
                        cornerRadius: 8,
                        displayColors: false
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(59, 50, 39, 0.4)' },
                        ticks: { font: { family: "'IBM Plex Mono', monospace" } }
                    },
                    y: {
                        min: 50,
                        max: 100,
                        ticks: {
                            callback: value => value + '%',
                            font: { family: "'IBM Plex Mono', monospace" }
                        },
                        grid: { color: 'rgba(59, 50, 39, 0.4)' }
                    }
                }
            }
        });
    }

    // 2. Department Compliance Chart (Bar Chart)
    const deptCtx = document.getElementById('deptChart');
    if (deptCtx) {
        new Chart(deptCtx, {
            type: 'bar',
            data: {
                labels: ['Cybersecurity', 'IT Infra', 'Software Dev', 'Human Resources', 'Operations'],
                datasets: [{
                    label: 'Compliance %',
                    data: [96, 88, 84, 78, 92],
                    backgroundColor: [
                        'rgba(227, 115, 24, 0.9)',
                        'rgba(201, 162, 39, 0.9)',
                        'rgba(124, 154, 87, 0.9)',
                        'rgba(168, 153, 133, 0.9)',
                        'rgba(227, 115, 24, 0.7)'
                    ],
                    borderRadius: 6,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    duration: 1200,
                    easing: 'easeOutQuart'
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#221C16',
                        borderColor: '#3B3227',
                        borderWidth: 1,
                        padding: 12,
                        cornerRadius: 8
                    }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { font: { family: "'IBM Plex Mono', monospace" } }
                    },
                    y: {
                        min: 0,
                        max: 100,
                        ticks: {
                            callback: value => value + '%',
                            font: { family: "'IBM Plex Mono', monospace" }
                        },
                        grid: { color: 'rgba(59, 50, 39, 0.4)' }
                    }
                }
            }
        });
    }

    // 3. Risk Distribution Chart (Doughnut Chart)
    const riskCtx = document.getElementById('riskChart');
    if (riskCtx) {
        new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: ['Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk'],
                datasets: [{
                    data: [4, 6, 3, 1],
                    backgroundColor: [
                        '#7C9A57',  // Low - Green
                        '#C9A227',  // Medium - Amber
                        '#E37318',  // High - Orange
                        '#BD4234'   // Critical - Red
                    ],
                    borderWidth: 2,
                    borderColor: '#221C16'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    animateRotate: true,
                    animateScale: true,
                    duration: 1200
                },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#EDE6D9',
                            font: { family: "'IBM Plex Mono', monospace", size: 12 },
                            usePointStyle: true,
                            padding: 16
                        }
                    },
                    tooltip: {
                        backgroundColor: '#221C16',
                        borderColor: '#3B3227',
                        borderWidth: 1,
                        padding: 10
                    }
                },
                cutout: '72%'
            }
        });
    }

    // 4. Completed vs Pending Tasks (Pie Chart)
    const taskCtx = document.getElementById('taskChart');
    if (taskCtx) {
        new Chart(taskCtx, {
            type: 'pie',
            data: {
                labels: ['Completed', 'Under Review', 'In Progress', 'Overdue'],
                datasets: [{
                    data: [14, 4, 6, 2],
                    backgroundColor: [
                        '#7C9A57',
                        '#E37318',
                        '#C9A227',
                        '#BD4234'
                    ],
                    borderWidth: 2,
                    borderColor: '#221C16'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    animateRotate: true,
                    duration: 1200
                },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#EDE6D9',
                            font: { family: "'IBM Plex Mono', monospace", size: 12 },
                            usePointStyle: true,
                            padding: 16
                        }
                    },
                    tooltip: {
                        backgroundColor: '#221C16',
                        borderColor: '#3B3227',
                        borderWidth: 1,
                        padding: 10
                    }
                }
            }
        });
    }
});

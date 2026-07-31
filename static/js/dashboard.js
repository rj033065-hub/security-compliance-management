// Security Command Center - Chart.js Visualizations v5.0
// Clean Light Theme Palette (#F7F8FA / #FFFFFF) with Deep Cobalt Blue (#2454E0) and IBM Plex Typography

document.addEventListener("DOMContentLoaded", function () {
    if (typeof Chart === 'undefined') return;

    // Shared Chart.js Font & Style Defaults
    Chart.defaults.font.family = "'IBM Plex Sans', sans-serif";
    Chart.defaults.color = '#5B6577';
    Chart.defaults.borderColor = '#DFE3EA';

    // 1. Compliance Trend Chart (Line Chart)
    const trendCtx = document.getElementById('trendChart');
    if (trendCtx) {
        const ctx = trendCtx.getContext('2d');
        const gradient = ctx.createLinearGradient(0, 0, 0, 260);
        gradient.addColorStop(0, 'rgba(36, 84, 224, 0.3)');
        gradient.addColorStop(1, 'rgba(36, 84, 224, 0.0)');

        new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: ['Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
                datasets: [{
                    label: 'Overall Compliance %',
                    data: [68, 72, 79, 81, 85, 91],
                    borderColor: '#2454E0',
                    backgroundColor: gradient,
                    fill: true,
                    tension: 0.38,
                    borderWidth: 3,
                    pointBackgroundColor: '#2454E0',
                    pointBorderColor: '#FFFFFF',
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
                        backgroundColor: '#10162B',
                        borderColor: '#DFE3EA',
                        borderWidth: 1,
                        titleColor: '#FFFFFF',
                        bodyColor: '#DFE3EA',
                        titleFont: { family: "'IBM Plex Mono', monospace", weight: 'bold' },
                        padding: 12,
                        cornerRadius: 8,
                        displayColors: false
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(223, 227, 234, 0.5)' },
                        ticks: { font: { family: "'IBM Plex Mono', monospace" } }
                    },
                    y: {
                        min: 50,
                        max: 100,
                        ticks: {
                            callback: value => value + '%',
                            font: { family: "'IBM Plex Mono', monospace" }
                        },
                        grid: { color: 'rgba(223, 227, 234, 0.5)' }
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
                        'rgba(36, 84, 224, 0.9)',
                        'rgba(183, 121, 31, 0.9)',
                        'rgba(63, 143, 95, 0.9)',
                        'rgba(91, 101, 119, 0.8)',
                        'rgba(36, 84, 224, 0.7)'
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
                        backgroundColor: '#10162B',
                        borderColor: '#DFE3EA',
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
                        grid: { color: 'rgba(223, 227, 234, 0.5)' }
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
                        '#3F8F5F',  // Low - Emerald Green
                        '#B7791F',  // Medium - Amber
                        '#2454E0',  // High - Cobalt Blue
                        '#C1443A'   // Critical - Crimson Red
                    ],
                    borderWidth: 2,
                    borderColor: '#FFFFFF'
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
                            color: '#10162B',
                            font: { family: "'IBM Plex Mono', monospace", size: 12 },
                            usePointStyle: true,
                            padding: 16
                        }
                    },
                    tooltip: {
                        backgroundColor: '#10162B',
                        borderColor: '#DFE3EA',
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
                        '#3F8F5F',
                        '#2454E0',
                        '#B7791F',
                        '#C1443A'
                    ],
                    borderWidth: 2,
                    borderColor: '#FFFFFF'
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
                            color: '#10162B',
                            font: { family: "'IBM Plex Mono', monospace", size: 12 },
                            usePointStyle: true,
                            padding: 16
                        }
                    },
                    tooltip: {
                        backgroundColor: '#10162B',
                        borderColor: '#DFE3EA',
                        borderWidth: 1,
                        padding: 10
                    }
                }
            }
        });
    }
});

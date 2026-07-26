// Glassmorphism Dashboard Chart.js Visualizations v3.0
document.addEventListener("DOMContentLoaded", function () {
    // Shared Chart.js Font & Style Defaults
    Chart.defaults.font.family = "'Plus Jakarta Sans', sans-serif";
    Chart.defaults.color = '#64748b';

    // 1. Compliance Trend Chart (Line Chart)
    const trendCtx = document.getElementById('trendChart');
    if (trendCtx) {
        const ctx = trendCtx.getContext('2d');
        const gradient = ctx.createLinearGradient(0, 0, 0, 260);
        gradient.addColorStop(0, 'rgba(37, 99, 235, 0.35)');
        gradient.addColorStop(1, 'rgba(37, 99, 235, 0.0)');

        new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: ['Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
                datasets: [{
                    label: 'Overall Compliance %',
                    data: [68, 72, 79, 81, 85, 91],
                    borderColor: '#2563eb',
                    backgroundColor: gradient,
                    fill: true,
                    tension: 0.38,
                    borderWidth: 3,
                    pointBackgroundColor: '#2563eb',
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                    pointRadius: 5,
                    pointHoverRadius: 7
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(15, 23, 42, 0.85)',
                        titleFont: { family: "'Plus Jakarta Sans', sans-serif", weight: 'bold' },
                        padding: 10,
                        cornerRadius: 8,
                        displayColors: false
                    }
                },
                scales: {
                    x: { grid: { display: false } },
                    y: {
                        min: 50,
                        max: 100,
                        ticks: { callback: value => value + '%' },
                        grid: { color: 'rgba(226, 232, 240, 0.6)' }
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
                        'rgba(37, 99, 235, 0.85)',
                        'rgba(59, 130, 246, 0.85)',
                        'rgba(16, 185, 129, 0.85)',
                        'rgba(245, 158, 11, 0.85)',
                        'rgba(14, 165, 233, 0.85)'
                    ],
                    borderRadius: 8,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(15, 23, 42, 0.85)',
                        padding: 10,
                        cornerRadius: 8
                    }
                },
                scales: {
                    x: { grid: { display: false } },
                    y: {
                        min: 0,
                        max: 100,
                        ticks: { callback: value => value + '%' },
                        grid: { color: 'rgba(226, 232, 240, 0.6)' }
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
                        '#10b981',
                        '#f59e0b',
                        '#ef4444',
                        '#7f1d1d'
                    ],
                    borderWidth: 2,
                    borderColor: '#ffffff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { font: { family: "'Plus Jakarta Sans', sans-serif" }, usePointStyle: true, padding: 15 }
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
                        '#10b981',
                        '#3b82f6',
                        '#f59e0b',
                        '#ef4444'
                    ],
                    borderWidth: 2,
                    borderColor: '#ffffff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { font: { family: "'Plus Jakarta Sans', sans-serif" }, usePointStyle: true, padding: 15 }
                    }
                }
            }
        });
    }
});

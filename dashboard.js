// Dashboard Chart.js Visualizations
document.addEventListener("DOMContentLoaded", function () {
    // Check if chart elements exist before initializing
    
    // 1. Compliance Trend Chart (Line Chart)
    const trendCtx = document.getElementById('trendChart');
    if (trendCtx) {
        new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: ['Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
                datasets: [{
                    label: 'Overall Compliance %',
                    data: [68, 72, 79, 81, 85, 91],
                    borderColor: '#2563eb',
                    backgroundColor: 'rgba(37, 99, 235, 0.1)',
                    fill: true,
                    tension: 0.3,
                    borderWidth: 3,
                    pointBackgroundColor: '#2563eb'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        min: 50,
                        max: 100,
                        ticks: { callback: value => value + '%' }
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
                        '#0d9488',
                        '#2563eb',
                        '#6366f1',
                        '#f59e0b',
                        '#10b981'
                    ],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        min: 0,
                        max: 100,
                        ticks: { callback: value => value + '%' }
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
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' }
                },
                cutout: '70%'
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
                        '#dc2626'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
    }
});

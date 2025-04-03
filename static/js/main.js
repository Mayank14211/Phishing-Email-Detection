// Document ready function
document.addEventListener('DOMContentLoaded', () => {
    // Initialize tab functionality
    const defaultTab = document.getElementById('defaultOpen');
    if (defaultTab) {
        defaultTab.click();
    }
    
    // Initialize progress bars with animation
    initProgressBars();
    
    // Initialize feature visibility toggles
    initFeatureToggles();
    
    // Add interactive card hover effects
    addCardInteractions();
    
    // Add subtle scroll animations
    addScrollAnimations();
    
    // Add chart visualizations if on results page
    if (document.getElementById('risk-factors-chart')) {
        initCharts();
    }
    
    // Initialize batch results chart if it exists
    initializeBatchResultsChart();
});

// Add interactive hover effects to cards
function addCardInteractions() {
    const cards = document.querySelectorAll('.card');
    
    cards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            card.style.transform = 'translateY(-8px)';
            card.style.boxShadow = '0 12px 20px var(--shadow-color)';
        });
        
        card.addEventListener('mouseleave', () => {
            card.style.transform = '';
            card.style.boxShadow = '';
        });
    });
}

// Tab switching functionality with smooth transitions
function openTab(evt, tabName) {
    const tabcontent = document.getElementsByClassName('tabcontent');
    
    // Hide all tabs with fade out effect
    for (let i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.opacity = 0;
        setTimeout(() => {
            tabcontent[i].style.display = 'none';
        }, 200);
    }
    
    // Remove active class from all tab buttons
    const tablinks = document.getElementsByClassName('tablinks');
    for (let i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(' active', '');
    }
    
    // Show the selected tab with fade in effect
    setTimeout(() => {
        const selectedTab = document.getElementById(tabName);
        selectedTab.style.display = 'block';
        
        // Use requestAnimationFrame to ensure display change is processed before opacity
        requestAnimationFrame(() => {
            selectedTab.style.opacity = 1;
        });
        
        evt.currentTarget.className += ' active';
    }, 210);
}

// Initialize progress bars with animation
function initProgressBars() {
    const progressBars = document.querySelectorAll('.progress-bar');
    progressBars.forEach(bar => {
        const width = bar.getAttribute('data-width');
        if (width) {
            // Initial state - zero width
            bar.style.width = '0%';
            
            // Delay animation slightly for visual effect
            setTimeout(() => {
                bar.style.width = width + '%';
                
                // Add progress label if not already present
                if (!bar.querySelector('.progress-label')) {
                    const label = document.createElement('span');
                    label.className = 'progress-label';
                    label.textContent = width + '%';
                    bar.appendChild(label);
                }
            }, 300);
        }
    });
}

// Initialize feature toggles to show/hide details
function initFeatureToggles() {
    const featureItems = document.querySelectorAll('.feature-item');
    featureItems.forEach(item => {
        // Check if the item has detailed content
        const detailContent = item.querySelector('.feature-details');
        if (detailContent) {
            detailContent.style.display = 'none';
            
            // Make the title clickable
            const title = item.querySelector('.feature-title');
            if (title) {
                title.style.cursor = 'pointer';
                title.innerHTML += ' <small>▼</small>';
                
                title.addEventListener('click', () => {
                    const isVisible = detailContent.style.display === 'block';
                    detailContent.style.display = isVisible ? 'none' : 'block';
                    title.innerHTML = title.innerHTML.replace(isVisible ? '▼' : '▲', isVisible ? '▲' : '▼');
                });
            }
        }
    });
}

// Initialize charts for risk visualization 
function initCharts() {
    updateChartColors();
}

// Copy results to clipboard
function copyResultsToClipboard() {
    const resultsContainer = document.getElementById('results-summary');
    if (!resultsContainer) return;
    
    const textToCopy = resultsContainer.innerText;
    
    // Create temporary textarea
    const textarea = document.createElement('textarea');
    textarea.value = textToCopy;
    document.body.appendChild(textarea);
    textarea.select();
    
    try {
        const successful = document.execCommand('copy');
        const message = successful ? 'Results copied to clipboard!' : 'Unable to copy results';
        
        // Show copy notification
        const notification = document.createElement('div');
        notification.className = 'copy-notification';
        notification.textContent = message;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.opacity = '0';
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 500);
        }, 2000);
    } catch (err) {
        console.error('Failed to copy: ', err);
    }
    
    document.body.removeChild(textarea);
}

// Update chart colors for dark theme
function updateChartColors() {
    // Always use dark mode colors
    const fontColor = '#f1f5f9';
    const gridColor = 'rgba(255, 255, 255, 0.1)';
    
    // Update all Chart.js instances
    if (typeof Chart !== 'undefined') {
        Chart.defaults.global.defaultFontColor = fontColor;
        Chart.defaults.global.elements.line.borderColor = '#818cf8';
        Chart.defaults.global.elements.arc.borderWidth = 2;
        Chart.defaults.global.legend.labels.fontColor = fontColor;
        
        // Find all charts and update them
        const charts = Chart.instances || [];
        for (let i = 0; i < charts.length; i++) {
            if (charts[i].options.legend) {
                charts[i].options.legend.labels.fontColor = fontColor;
            }
            
            // Update grid colors for cartesian charts
            if (charts[i].options.scales) {
                const scales = charts[i].options.scales;
                if (scales.xAxes) {
                    scales.xAxes.forEach(axis => {
                        if (axis.gridLines) {
                            axis.gridLines.color = gridColor;
                            axis.gridLines.zeroLineColor = gridColor;
                        }
                        axis.ticks = axis.ticks || {};
                        axis.ticks.fontColor = fontColor;
                    });
                }
                if (scales.yAxes) {
                    scales.yAxes.forEach(axis => {
                        if (axis.gridLines) {
                            axis.gridLines.color = gridColor;
                            axis.gridLines.zeroLineColor = gridColor;
                        }
                        axis.ticks = axis.ticks || {};
                        axis.ticks.fontColor = fontColor;
                    });
                }
            }
            
            // For pie/doughnut charts, update hover border color
            if (charts[i].config.type === 'pie' || charts[i].config.type === 'doughnut') {
                const dataset = charts[i].data.datasets[0];
                dataset.borderColor = 'rgba(255, 255, 255, 0.2)';
                dataset.borderWidth = 2;
                dataset.hoverBorderWidth = 4;
                dataset.hoverBorderColor = '#f1f5f9';
            }
            
            charts[i].update();
        }
    }
}

// Apply initial chart colors and initialize batch results chart
document.addEventListener('DOMContentLoaded', function() {
    updateChartColors();
    
    // Add subtle scroll animations
    addScrollAnimations();
    
    // Initialize batch results chart if it exists
    const batchResultsChart = document.getElementById('batch-results-chart');
    if (batchResultsChart) {
        const canvas = batchResultsChart;
        const ctx = canvas.getContext('2d');
        
        // Count results by prediction and correctness
        const truePositives = parseInt(canvas.getAttribute('data-true-positives') || 0);
        const falsePositives = parseInt(canvas.getAttribute('data-false-positives') || 0);
        const trueNegatives = parseInt(canvas.getAttribute('data-true-negatives') || 0);
        const falseNegatives = parseInt(canvas.getAttribute('data-false-negatives') || 0);
        
        const isDarkMode = document.documentElement.getAttribute('data-theme') === 'dark';
        
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['True Positives', 'False Positives', 'True Negatives', 'False Negatives'],
                datasets: [{
                    data: [truePositives, falsePositives, trueNegatives, falseNegatives],
                    backgroundColor: isDarkMode ? 
                        ['#f87171', '#fbbf24', '#34d399', '#60a5fa'] :
                        ['#ef4444', '#f59e0b', '#10b981', '#3b82f6'],
                    borderColor: isDarkMode ? 'rgba(15, 23, 42, 0.8)' : 'rgba(255, 255, 255, 1)',
                    borderWidth: 2,
                    hoverBorderWidth: 4,
                    hoverBorderColor: isDarkMode ? '#f1f5f9' : '#ffffff'
                }]
            },
            options: {
                responsive: true,
                cutoutPercentage: 65,
                legend: {
                    position: 'right',
                    labels: {
                        fontColor: isDarkMode ? '#f1f5f9' : '#1e293b',
                        padding: 15,
                        usePointStyle: true,
                        fontSize: 12,
                        boxWidth: 10
                    }
                },
                tooltips: {
                    enabled: false,
                    custom: function(tooltipModel) {
                        // Custom tooltip implementation
                        var tooltipEl = document.getElementById('chartjs-tooltip');
                        
                        // Create element if it doesn't exist
                        if (!tooltipEl) {
                            tooltipEl = document.createElement('div');
                            tooltipEl.id = 'chartjs-tooltip';
                            tooltipEl.innerHTML = '<table></table>';
                            document.body.appendChild(tooltipEl);
                        }
                        
                        // Hide if no tooltip
                        if (tooltipModel.opacity === 0) {
                            tooltipEl.style.opacity = 0;
                            return;
                        }
                        
                        // Set caret position
                        tooltipEl.classList.remove('above', 'below', 'no-transform');
                        if (tooltipModel.yAlign) {
                            tooltipEl.classList.add(tooltipModel.yAlign);
                        } else {
                            tooltipEl.classList.add('no-transform');
                        }
                        
                        function getBody(bodyItem) {
                            return bodyItem.lines;
                        }
                        
                        // Set Text
                        if (tooltipModel.body) {
                            const titleLines = tooltipModel.title || [];
                            const bodyLines = tooltipModel.body.map(getBody);
                            
                            const dataset = this._data.datasets[tooltipModel.dataPoints[0].datasetIndex];
                            const total = dataset.data.reduce((previousValue, currentValue) => previousValue + currentValue);
                            const currentValue = dataset.data[tooltipModel.dataPoints[0].index];
                            const percentage = Math.floor(((currentValue/total) * 100)+0.5);
                            
                            let innerHtml = '<div class="tooltip-header">';

                            titleLines.forEach(function(title) {
                                innerHtml += '<span>' + title + '</span>';
                            });
                            innerHtml += '</div><div class="tooltip-body">';
                            
                            innerHtml += '<div class="tooltip-value">' + currentValue + ' (' + percentage + '%)</div>';
                            
                            innerHtml += '</div>';

                            const tableRoot = tooltipEl.querySelector('table');
                            tableRoot.innerHTML = innerHtml;
                        }
                        
                        const position = this._chart.canvas.getBoundingClientRect();
                        const bodyFont = Chart.helpers.fontString(14, 'normal', Chart.defaults.global.defaultFontFamily);
                        
                        // Display, position, and style
                        tooltipEl.style.opacity = 1;
                        tooltipEl.style.position = 'absolute';
                        tooltipEl.style.left = position.left + window.pageXOffset + tooltipModel.caretX + 'px';
                        tooltipEl.style.top = position.top + window.pageYOffset + tooltipModel.caretY + 'px';
                        tooltipEl.style.fontFamily = Chart.defaults.global.defaultFontFamily;
                        tooltipEl.style.fontSize = '14px';
                        tooltipEl.style.fontStyle = tooltipModel._bodyFontStyle;
                        tooltipEl.style.padding = tooltipModel.yPadding + 'px ' + tooltipModel.xPadding + 'px';
                        tooltipEl.style.pointerEvents = 'none';
                        tooltipEl.style.backgroundColor = isDarkMode ? 'rgba(30, 41, 59, 0.9)' : 'rgba(255, 255, 255, 0.9)';
                        tooltipEl.style.color = isDarkMode ? '#f1f5f9' : '#1e293b';
                        tooltipEl.style.borderRadius = '6px';
                        tooltipEl.style.boxShadow = isDarkMode ? '0 4px 12px rgba(0, 0, 0, 0.3)' : '0 4px 12px rgba(0, 0, 0, 0.1)';
                        tooltipEl.style.border = isDarkMode ? '1px solid #334155' : '1px solid #e2e8f0';
                        tooltipEl.style.transition = 'all 0.2s ease';
                        tooltipEl.style.transform = 'translate(-50%, -100%) scale(1)';
                        tooltipEl.style.transformOrigin = 'bottom center';
                    }
                },
                animation: {
                    animateScale: true,
                    animateRotate: true,
                    duration: 2000,
                    easing: 'easeOutQuart'
                }
            }
        });
    }
    
    // Initialize risk factors chart if it exists
    const riskFactorsChart = document.getElementById('risk-factors-chart');
    if (riskFactorsChart) {
        const labels = JSON.parse(riskFactorsChart.getAttribute('data-labels') || '[]');
        const values = JSON.parse(riskFactorsChart.getAttribute('data-values') || '[]');
        
        if (labels.length > 0) {
            const isDarkMode = document.documentElement.getAttribute('data-theme') === 'dark';
            const fontColor = isDarkMode ? '#f1f5f9' : '#1e293b';
            
            new Chart(riskFactorsChart.getContext('2d'), {
                type: 'horizontalBar',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Risk Factors',
                        data: values,
                        backgroundColor: isDarkMode ? 
                            ['#f87171', '#fb923c', '#fbbf24', '#a3e635', '#34d399'].slice(0, labels.length) : 
                            ['#ef4444', '#f97316', '#f59e0b', '#84cc16', '#10b981'].slice(0, labels.length),
                        borderColor: 'rgba(0, 0, 0, 0.1)',
                        borderWidth: 1,
                        barPercentage: 0.7,
                        categoryPercentage: 0.8,
                        hoverBackgroundColor: isDarkMode ? '#f87171' : '#ef4444'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    legend: {
                        display: false
                    },
                    scales: {
                        xAxes: [{
                            ticks: {
                                beginAtZero: true,
                                max: 5,
                                fontColor: fontColor,
                                padding: 10,
                                fontStyle: 'bold',
                                callback: function(value) {
                                    return value.toFixed(1);
                                }
                            },
                            gridLines: {
                                color: isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)',
                                zeroLineColor: isDarkMode ? 'rgba(255, 255, 255, 0.2)' : 'rgba(0, 0, 0, 0.2)',
                                drawBorder: false
                            }
                        }],
                        yAxes: [{
                            ticks: {
                                fontColor: fontColor,
                                padding: 10,
                                fontStyle: 'bold'
                            },
                            gridLines: {
                                display: false
                            }
                        }]
                    },
                    tooltips: {
                        enabled: false,
                        custom: function(tooltipModel) {
                            // Custom tooltip implementation
                            var tooltipEl = document.getElementById('chartjs-tooltip-risk');
                            
                            // Create element if it doesn't exist
                            if (!tooltipEl) {
                                tooltipEl = document.createElement('div');
                                tooltipEl.id = 'chartjs-tooltip-risk';
                                tooltipEl.innerHTML = '<table></table>';
                                document.body.appendChild(tooltipEl);
                            }
                            
                            // Hide if no tooltip
                            if (tooltipModel.opacity === 0) {
                                tooltipEl.style.opacity = 0;
                                return;
                            }
                            
                            function getBody(bodyItem) {
                                return bodyItem.lines;
                            }
                            
                            // Set Text
                            if (tooltipModel.body) {
                                const bodyLines = tooltipModel.body.map(getBody);
                                const value = tooltipModel.dataPoints[0].xLabel;
                                let riskLevel = '';
                                
                                if (value >= 4) {
                                    riskLevel = '<span style="color: ' + (isDarkMode ? '#f87171' : '#ef4444') + '; font-weight: bold;">High Risk</span>';
                                } else if (value >= 3) {
                                    riskLevel = '<span style="color: ' + (isDarkMode ? '#fbbf24' : '#f59e0b') + '; font-weight: bold;">Medium Risk</span>';
                                } else {
                                    riskLevel = '<span style="color: ' + (isDarkMode ? '#34d399' : '#10b981') + '; font-weight: bold;">Low Risk</span>';
                                }
                                
                                const featureName = tooltipModel.dataPoints[0].yLabel;
                                
                                let innerHtml = '<div class="tooltip-risk-header">';
                                innerHtml += featureName;
                                innerHtml += '</div><div class="tooltip-risk-body">';
                                innerHtml += riskLevel + ' (' + value + '/5)';
                                innerHtml += '</div>';

                                const tableRoot = tooltipEl.querySelector('table');
                                tableRoot.innerHTML = innerHtml;
                            }
                            
                            const position = this._chart.canvas.getBoundingClientRect();
                            
                            // Display, position, and style
                            tooltipEl.style.opacity = 1;
                            tooltipEl.style.position = 'absolute';
                            tooltipEl.style.left = position.left + window.pageXOffset + tooltipModel.caretX + 'px';
                            tooltipEl.style.top = position.top + window.pageYOffset + tooltipModel.caretY + 'px';
                            tooltipEl.style.fontFamily = Chart.defaults.global.defaultFontFamily;
                            tooltipEl.style.fontSize = '14px';
                            tooltipEl.style.padding = '10px 14px';
                            tooltipEl.style.pointerEvents = 'none';
                            tooltipEl.style.backgroundColor = isDarkMode ? 'rgba(30, 41, 59, 0.95)' : 'rgba(255, 255, 255, 0.95)';
                            tooltipEl.style.color = isDarkMode ? '#f1f5f9' : '#1e293b';
                            tooltipEl.style.borderRadius = '8px';
                            tooltipEl.style.boxShadow = isDarkMode ? '0 4px 12px rgba(0, 0, 0, 0.3)' : '0 4px 12px rgba(0, 0, 0, 0.1)';
                            tooltipEl.style.border = isDarkMode ? '1px solid #334155' : '1px solid #e2e8f0';
                            tooltipEl.style.transition = 'all 0.2s ease';
                            tooltipEl.style.transform = 'translate(10px, 0)';
                            tooltipEl.style.zIndex = 1000;
                            
                            // Style tooltip header and body
                            const header = tooltipEl.querySelector('.tooltip-risk-header');
                            if (header) {
                                header.style.fontWeight = 'bold';
                                header.style.marginBottom = '5px';
                                header.style.borderBottom = isDarkMode ? '1px solid #334155' : '1px solid #e2e8f0';
                                header.style.paddingBottom = '5px';
                            }
                        }
                    },
                    animation: {
                        duration: 1500,
                        easing: 'easeOutQuart'
                    },
                    hover: {
                        animationDuration: 300
                    }
                }
            });
        }
    }
});

// Add subtle scroll animations to elements
function addScrollAnimations() {
    // Add CSS class for animations
    const style = document.createElement('style');
    style.innerHTML = `
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .animate-on-scroll {
            opacity: 0;
        }
        
        .animate-on-scroll.animated {
            animation: fadeInUp 0.6s ease forwards;
        }
    `;
    document.head.appendChild(style);
    
    // Add animation class to elements
    const elementsToAnimate = document.querySelectorAll('.card, .result-item, h2, .feature-item');
    elementsToAnimate.forEach(element => {
        element.classList.add('animate-on-scroll');
    });
    
    // Check if element is in viewport
    function isElementInViewport(el) {
        const rect = el.getBoundingClientRect();
        return (
            rect.top <= (window.innerHeight || document.documentElement.clientHeight) * 0.85 &&
            rect.bottom >= 0
        );
    }
    
    // Add animation when elements come into view
    function checkAnimations() {
        const elements = document.querySelectorAll('.animate-on-scroll:not(.animated)');
        elements.forEach(element => {
            if (isElementInViewport(element)) {
                // Add slight delay based on element position for cascade effect
                const delay = element.dataset.delay || 0;
                setTimeout(() => {
                    element.classList.add('animated');
                }, delay);
            }
        });
    }
    
    // Add delay to create cascade effect
    const cards = document.querySelectorAll('.card');
    cards.forEach((card, index) => {
        card.dataset.delay = index * 100;
    });
    
    const resultItems = document.querySelectorAll('.result-item');
    resultItems.forEach((item, index) => {
        item.dataset.delay = index * 80;
    });
    
    // Run on scroll and initial load
    window.addEventListener('scroll', checkAnimations);
    checkAnimations();
} 
let icoColor = "";
        let editingTaskId = null;
        const sidebar = document.querySelector('.sidebar');
        

        

        function toggleSidebar() {            
            // Check if the screen width is less than or equal to 768px (mobile)
            if (window.innerWidth <= 768) {
                if (sidebar.style.left === '-100%' || sidebar.style.left === '') {
                    sidebar.style.left = '0'; // Slide the sidebar in
                } else {
                    sidebar.style.left = '-100%'; // Slide the sidebar out
                }
            } else {
                // For desktop, always display the sidebar without animation
                sidebar.style.left = '0';
            }
        }

        function checkSidebarSize() {
            const sidebar = document.querySelector('.sidebar');
            
            if (window.innerWidth >= 769) {
                sidebar.style.left = '0'; // Show the sidebar
            }
        }

        checkSidebarSize();

        // Use a function expression with setInterval
        setInterval(function() {
            checkSidebarSize();
        }, 10);

        
        function showNotification(taskTitle, message) {
        const options = {
            body: message,
            icon: 'static/favicon-32x32.png' // Replace with your icon URL
        };



    new Notification(taskTitle, options);
}


let approachingNotifications = {}; // To track approaching notifications
let dueDateNotifications = {}; // To track due date notifications
let overdueNotifications = {}; // To track overdue notifications

function showNotification(taskTitle, message) {
    const options = {
        body: message,
        icon: 'path_to_your_notification_icon.png' // Replace with your icon URL
    };

    new Notification(taskTitle, options);
}

function time_remaining(due_date) {
    const now = new Date();
    const due = new Date(due_date);
    const diff = due - now;

    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    const months = Math.floor(days / 30);
    const years = Math.floor(months / 12);

    if (diff <= 0) {
        const overdueTime = Math.abs(diff);
        const overdueDays = Math.floor(overdueTime / (24 * 60 * 60 * 1000));
        const overdueHours = Math.floor((overdueTime % (24 * 60 * 60 * 1000)) / (60 * 60 * 1000));
        const overdueMinutes = Math.floor((overdueTime % (60 * 60 * 1000)) / (60 * 1000));
        const overdueSeconds = Math.floor((overdueTime % (60 * 1000)) / 1000);

        return `Overdue by ${overdueDays} days, ${overdueHours} hours, ${overdueMinutes} minutes, and ${overdueSeconds} seconds`;
    } else if (years >= 2) {
        const easterEggValue = 102; // Frozen runtime in minutes
        const watchCount = Math.floor(diff / (easterEggValue * 60 * 1000));
        return `In the amount of time you need to wait you could watch Frozen ${watchCount} times`;
    } else if (years > 0) {
        return years + ' years';
    } else if (months > 0) {
        return months + ' months';
    } else if (days > 0) {
        return days + ' days';
    } else if (hours > 0) {
        return hours + ' hours';
    } else if (minutes > 0) {
        return minutes + ' minutes';
    } else {
        return seconds + ' seconds';
    }
}
        function updateTimeRemaining() {
            const dueDateElements = document.querySelectorAll('#time-remaining');
            dueDateElements.forEach(dueDateElement => {
                const dueDate = dueDateElement.getAttribute('data-due-date');
                const timeRemaining = time_remaining(dueDate);

                dueDateElement.textContent = timeRemaining;
            });
        }

        // Update time remaining dynamically every minute
        setInterval(updateTimeRemaining, 1000);
        updateTimeRemaining();

        document.addEventListener('DOMContentLoaded', () => {
    const tutorialPopup = document.getElementById('tutorial-popup');
    const closeTutorialButton = document.getElementById('close-tutorial');

    function centerTutorialPopup() {
        const popupWidth = tutorialPopup.offsetWidth;
        const popupHeight = tutorialPopup.offsetHeight;

        const centerX = (window.innerWidth - popupWidth) / 2;
        const centerY = (window.innerHeight - popupHeight) / 2;

        tutorialPopup.style.left = centerX + 'px';
        tutorialPopup.style.top = centerY + 'px';
    }

    function hideTutorialPopup() {
        tutorialPopup.style.display = 'none';
    }

    centerTutorialPopup();
    window.addEventListener('resize', centerTutorialPopup);

    closeTutorialButton.addEventListener('click', () => {
        hideTutorialPopup();
        // Set a cookie to indicate that the tutorial has been seen
        document.cookie = 'tutorialSeen=true; expires=Fri, 31 Dec 9999 23:59:59 GMT';
    });

    // Check if the tutorial has been seen in the past
    if (document.cookie.includes('tutorialSeen=true')) {
        hideTutorialPopup();
    } else {
        tutorialPopup.style.display = 'block'; // Make the popup visible
    }
});


// Function to set a cookie
function setCookie(name, value, days) {
    const expires = new Date();
    expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);
    document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/`;
}

// Function to get a cookie by name
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}



function checkDueDates() {
    const tasks = document.querySelectorAll('.task-item');
    const now = new Date();

    tasks.forEach(task => {
        const taskId = task.dataset.taskId;
        const dueDate = new Date(task.dataset.dueDate);

        const timeDiff = dueDate - now;
        const minutesRemaining = Math.floor(timeDiff / (60 * 1000));
        const hoursRemaining = Math.floor(timeDiff / (60 * 60 * 1000));
        const daysRemaining = Math.floor(timeDiff / (24 * 60 * 60 * 1000));

        if (minutesRemaining > 0 && minutesRemaining <= 10 && !approachingNotifications[taskId]) {
            // ... (rest of the code for approaching notifications)
        } else if (dueDate <= now && timeDiff > (10 * 60 * 1000) && !overdueNotifications[taskId]) {
            if (timeDiff <= (1 * 60 * 60 * 1000)) {
                showNotification(task.querySelector('strong').textContent, 'Task overdue.');
                overdueNotifications[taskId] = true; // Mark task as overdue
            } else if (timeDiff <= (1 * 24 * 60 * 60 * 1000)) {
                showNotification(task.querySelector('strong').textContent, 'Task overdue.');
                overdueNotifications[taskId] = true; // Mark task as overdue
            } else {
                const daysOverdue = Math.floor(timeDiff / (24 * 60 * 60 * 1000));
                if (daysOverdue >= 2) {
                    showNotification(task.querySelector('strong').textContent, `Over 2 years overdue finish it bro.`);
                    overdueNotifications[taskId] = true; // Mark task as overdue
                } else {
                    showNotification(task.querySelector('strong').textContent, 'Task overdue.');
                    overdueNotifications[taskId] = true; // Mark task as overdue
                }
            }
        }

    });
}

// Request permission for notifications
if ('Notification' in window) {
    Notification.requestPermission();
}

// Check due dates periodically
setInterval(checkDueDates, 1000); // Check every second


        function searchTasks() {
    const searchInput = document.getElementById("searchInput").value.toLowerCase();
    const taskItems = document.querySelectorAll(".task-item");

    const matchingTasks = Array.from(taskItems).filter(item => {
        const taskTitle = item.querySelector("strong").textContent.toLowerCase();
        const taskDescription = item.querySelector("p").textContent.toLowerCase();
        return taskTitle.includes(searchInput) || taskDescription.includes(searchInput);
    });

    // Hide all task items
    taskItems.forEach(item => {
        item.style.display = "none";
    });

    // Display matching tasks
    matchingTasks.forEach(item => {
        item.style.display = "block";
    });

    // Update the task results message
    const taskResults = document.getElementById("taskResults");
    if (matchingTasks.length > 0) {
        taskResults.textContent = `${matchingTasks.length} tasks found by search.`;
    } else {
        taskResults.textContent = "No tasks with those keywords.";
    }
}

function searchAndFilterTasks() {
    const searchInput = document.getElementById("searchInput").value.toLowerCase();
    const selectedGroup = document.getElementById("groupFilter").value;
    const taskItems = document.querySelectorAll(".task-item");

    const matchingTasks = Array.from(taskItems).filter(item => {
        const taskTitle = item.querySelector("strong").textContent.toLowerCase();
        const taskDescription = item.querySelector("p").textContent.toLowerCase();
        const taskGroup = item.getAttribute("data-group");
        
        const matchesSearch = taskTitle.includes(searchInput) || taskDescription.includes(searchInput);
        const matchesGroup = selectedGroup === "" || taskGroup === selectedGroup;
        
        return matchesSearch && matchesGroup;
    });

    // Hide all task items
    taskItems.forEach(item => {
        item.style.display = "none";
    });

    // Display matching tasks
    matchingTasks.forEach(item => {
        item.style.display = "block";
    });

    // Update the task results message
    const taskResults = document.getElementById("taskResults");
    if (matchingTasks.length > 0) {
        taskResults.textContent = `${matchingTasks.length} tasks found by search and group.`;
    } else {
        taskResults.textContent = "No tasks with those keywords and in the selected group.";
    }
}

function filterByGroup() {
    const selectedGroup = document.getElementById("groupFilter").value;
    const taskItems = document.querySelectorAll(".task-item");

    const filteredTasks = Array.from(taskItems).filter(item => {
        const taskGroup = item.getAttribute("data-group");
        return selectedGroup === "" || taskGroup === selectedGroup;
    });

    // Hide all task items
    taskItems.forEach(item => {
        item.style.display = "none";
    });

    // Display filtered tasks
    filteredTasks.forEach(item => {
        item.style.display = "block";
    });

    // Update the task results message
    const taskResults = document.getElementById("taskResults");
    if (filteredTasks.length > 0) {
        taskResults.textContent = `${filteredTasks.length} tasks found by group filter.`;
    } else {
        taskResults.textContent = "No tasks in the selected group.";
    }
}


        function showEditForm(taskId) {
            editingTaskId = taskId;

            // Send a GET request to fetch task details by ID from the server
            fetch(`/get_task/${taskId}`)  // Adjust the URL to match your server route
            .then(response => response.json())
            .then(data => {
                if (data.task) {
                    const task = data.task;
                    document.getElementById("editTitle").value = task.title;
                    document.getElementById("editDescription").value = task.description;
                    // ... update other form fields ...

                    document.getElementById("editFormContainer").style.display = "block";
                } else {
                    console.error("Task not found");
                }
            })
            .catch(error => {
                console.error('Error:', error);
            });
        }


        function saveEditedTask() {
            const editedTitle = document.getElementById("editTitle").value;
            const editedDescription = document.getElementById("editDescription").value;
            // ... get other edited form field values ...

            const updatedTask = {
                id: editingTaskId,
                title: editedTitle,
                description: editedDescription,
                // ... other updated fields ...
            };

            // Send a PUT request to your server endpoint with updatedTask
            fetch(`/update_task/${editingTaskId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(updatedTask)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Update the task list or perform any necessary UI changes
                    // Hide the edit form
                    document.getElementById("editFormContainer").style.display = "none";
                } else {
                    // Handle error
                    console.error(data.error);
                }
            })
            .catch(error => {
                console.error('Error:', error);
            });
        }

        document.body.classList.add("transition");
        let dropdownOpen = false;

        function toggleDropdown() {
            const dropdown = document.getElementById("myDropdown");
            
            if (!dropdownOpen) {
                dropdown.style.display = "block";
                dropdownOpen = true;
            } else {
                dropdown.style.display = "none";
                dropdownOpen = false;
            }
        }

        window.onclick = function(event) {
            if (!event.target.matches('.profile-picture')) {
                const dropdown = document.getElementById("myDropdown");
                if (dropdownOpen) {
                    dropdown.style.display = "none";
                    dropdownOpen = false;
                }
            }
        }

        function deleteTask(taskId) {
            fetch(`/delete_task/${taskId}`, {
                method: 'DELETE',
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert(data.error);
                }
            })
            .catch(error => {
                console.error('Error:', error);
            });
        }

        function toggleDarkLightMode() {
    const body = document.body;
    const iconElement = document.getElementById("dark-mode-icon");

    if (body.classList.contains("dark-mode")) {
        body.classList.remove("dark-mode");
        body.classList.add("light-mode");
        document.cookie = "dark_mode=false; path=/";
        icoColor = "fa fa-sun-o";
    } else {
        body.classList.remove("light-mode");
        body.classList.add("dark-mode");
        document.cookie = "dark_mode=true; path=/";
        icoColor = "fa fa-moon-o";
    }

    iconElement.className = icoColor;

    // Add a timeout to remove the transition class after the transition is complete
    setTimeout(() => {
        body.classList.remove("transition");
    }, 500); // 500ms is the duration of the transition
}


    const darkModeCookie = document.cookie.match(/(?:(?:^|.*;\s*)dark_mode\s*=\s*([^;]*).*$)|^.*$/)[1];
    const iconElement = document.getElementById("dark-mode-icon");

    if (darkModeCookie && darkModeCookie === "true") {
        document.body.classList.add("dark-mode");
        icoColor = "fa fa-moon-o";
    } else {
        icoColor = "fa fa-sun-o";
    }

    iconElement.className = icoColor;

    function logout() {
        // Clear the "user" cookie by setting an empty value and an expired date
        document.cookie = "user=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
        
        // Redirect the user to the logout page or any desired page
        window.location.href = "/";
    }

    
function showCollabForm() {
    document.getElementById('collab-popup').style.display = 'block';
    document.body.style.setProperty('--dimmed-background-display', 'block');
    }

    function closeCollabForm() {
        document.getElementById('collab-popup').style.display = 'none';
        document.body.style.setProperty('--dimmed-background-display', 'none');
    }


    // JavaScript to add more collaborator input fields
    document.addEventListener("DOMContentLoaded", function () {
        const addButton = document.getElementById("add-collaborator");
        const userCollabError = document.getElementById("userCollabError");
        const collaboratorInputs = document.getElementById("collaborator-inputs");

        let collaboratorCount = 1;

        addButton.addEventListener("click", function () {
            if (collaboratorCount < 3) { // Limit to 3 collaborators
                const input = document.createElement("div");
                input.classList.add("collaborator-input");
                input.innerHTML = `
                    <input type="text" name="user${collaboratorCount + 1}" placeholder="User ${collaboratorCount + 1}" required>
                `;
                collaboratorInputs.appendChild(input);
                collaboratorCount++;
            }

            if (collaboratorCount === 3) {
                userCollabError.textContent = 'Max amount of users!';
                addButton.disabled = true; // Disable the button when the max is reached
            }
        });


        // JavaScript for fetching and displaying usernames
        const usernameInput = document.getElementById("user1");
        usernameInput.addEventListener("input", function () {
            const username = usernameInput.value;
            fetchUsernames(username);
        });

        function fetchUsernames(username) {
        // Make an AJAX request to the server to fetch usernames
        fetch(`http://127.0.0.1/get_usernames?username=${username}`)
            .then((response) => response.json())
            .then((data) => {
                // Display the usernames as suggestions
                displayUsernames(data.usernames);
            })
            .catch((error) => {
                console.error("Error fetching usernames:", error);
            });
        }


        // JavaScript for displaying username suggestions
        function displayUsernames(usernames) {
            const suggestions = document.getElementById("suggestions");
            const usernameInput = document.getElementById("user1"); // Change this to the actual ID of your input field

            // Clear previous suggestions
            suggestions.innerHTML = "";

            if (usernames.length > 0) {
                // Show the suggestions container
                suggestions.style.display = "block";

                // Loop through usernames and create suggestion items
                usernames.forEach((username) => {
                    const suggestion = document.createElement("div");
                    suggestion.textContent = username;
                    suggestion.classList.add("suggestion");

                    // Handle click on a suggestion
                    suggestion.addEventListener("click", function () {
                        usernameInput.value = username;
                        suggestions.style.display = "none"; // Hide suggestions after selection
                    });

                    suggestions.appendChild(suggestion);
                });
            } else {
                // Hide the suggestions container when no suggestions are available
                suggestions.style.display = "none";
            }
        }

        // Creation for collab cannot be done here because of the Jinja Variable it is in home.html

    });

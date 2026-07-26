// Application Global JavaScript
document.addEventListener("DOMContentLoaded", function () {
    // 1. Table Search Filter
    const searchInputs = document.querySelectorAll(".table-search-input");
    searchInputs.forEach(input => {
        input.addEventListener("keyup", function () {
            const targetTableId = this.getAttribute("data-table-target");
            const filter = this.value.toLowerCase();
            const table = document.getElementById(targetTableId);
            if (!table) return;
            
            const rows = table.querySelectorAll("tbody tr");
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                if (text.includes(filter)) {
                    row.style.display = "";
                } else {
                    row.style.display = "none";
                }
            });
        });
    });

    // 2. AI Assistant Interactive Chat Window
    const aiForm = document.getElementById("aiChatForm");
    const aiInput = document.getElementById("aiQueryInput");
    const aiBox = document.getElementById("aiChatBox");

    if (aiForm && aiInput && aiBox) {
        aiForm.addEventListener("submit", function (e) {
            e.preventDefault();
            const query = aiInput.value.trim();
            if (!query) return;

            // Append User Message
            appendChatMessage("user", query);
            aiInput.value = "";

            // Show Bot Loading Indicator
            const loadingId = "bot-loading-" + Date.now();
            appendChatMessage("bot", '<i class="fas fa-spinner fa-spin me-2"></i> Analyzing compliance query...', loadingId);

            // Fetch AI Response via API Endpoint
            fetch("/api/ai/chat", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ query: query })
            })
            .then(res => res.json())
            .then(data => {
                const loadingElem = document.getElementById(loadingId);
                if (loadingElem) loadingElem.remove();

                let html = `<div>${data.answer}</div>`;
                if (data.suggested_actions && data.suggested_actions.length > 0) {
                    html += `<div class="mt-2 text-warning small"><strong><i class="fas fa-lightbulb me-1"></i> Suggested Actions:</strong></div><ul class="mb-0 ps-3 small">`;
                    data.suggested_actions.forEach(action => {
                        html += `<li>${action}</li>`;
                    });
                    html += `</ul>`;
                }
                appendChatMessage("bot", html);
            })
            .catch(err => {
                const loadingElem = document.getElementById(loadingId);
                if (loadingElem) loadingElem.remove();
                appendChatMessage("bot", '<span class="text-danger"><i class="fas fa-exclamation-circle me-1"></i> AI Assistant temporarily offline. Please try again.</span>');
            });
        });
    }

    function appendChatMessage(sender, content, id = null) {
        const msgDiv = document.createElement("div");
        msgDiv.className = `chat-message ${sender}`;
        if (id) msgDiv.id = id;

        msgDiv.innerHTML = `
            <div class="message-bubble">
                ${content}
            </div>
        `;
        aiBox.appendChild(msgDiv);
        aiBox.scrollTop = aiBox.scrollHeight;
    }
});

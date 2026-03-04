document.addEventListener('DOMContentLoaded', () => {
    // 1. Inject Chatbot HTML Structure securely into the DOM
    const chatbotHTML = `
        <div id="tnChatbotWidget" class="chatbot-widget">
            <!-- Chat Window -->
            <div id="tnChatbotWindow" class="chatbot-window hidden">
                <div class="chatbot-header">
                    <div class="bot-info">
                        <i class="fas fa-robot bot-icon"></i>
                        <div>
                            <h4>TN Sahaya Bot</h4>
                            <span class="status-indicator">Online</span>
                        </div>
                    </div>
                    <button class="close-chat-btn" id="closeChatBtn"><i class="fas fa-times"></i></button>
                </div>
                
                <div id="tnChatbotMessages" class="chatbot-messages">
                    <div class="message bot-message">
                        Vanakam! 🙏 I am Hari, the TN Portal Assistant. How can I help you today?
                        <br><br>You can ask me about:
                        <ul>
                            <li>How to register a complaint</li>
                            <li>Privacy & Safety</li>
                            <li>Emergency Numbers</li>
                            <li>Trauma Counseling</li>
                        </ul>
                    </div>
                </div>
                
                <div class="chatbot-input-area">
                    <input type="text" id="tnChatbotInput" placeholder="Type your question here..." autocomplete="off">
                    <button id="tnChatbotSendBtn"><i class="fas fa-paper-plane"></i></button>
                </div>
            </div>

            <!-- Floating Button -->
            <button id="tnChatbotToggleBtn" class="chatbot-toggle-btn">
                <i class="fas fa-comments"></i>
                <span class="tooltip-text">I can help! (உதவி)</span>
            </button>
        </div>
    `;

    document.body.insertAdjacentHTML('beforeend', chatbotHTML);

    // 2. DOM Elements
    const toggleBtn = document.getElementById('tnChatbotToggleBtn');
    const closeBtn = document.getElementById('closeChatBtn');
    const chatWindow = document.getElementById('tnChatbotWindow');
    const chatInput = document.getElementById('tnChatbotInput');
    const sendBtn = document.getElementById('tnChatbotSendBtn');
    const messagesContainer = document.getElementById('tnChatbotMessages');

    // 3. Toggle Chat Window
    toggleBtn.addEventListener('click', () => {
        chatWindow.classList.remove('hidden');
        chatWindow.classList.add('slide-up');
        toggleBtn.style.transform = 'scale(0)';
        setTimeout(() => chatInput.focus(), 300);
    });

    closeBtn.addEventListener('click', () => {
        chatWindow.classList.add('hidden');
        chatWindow.classList.remove('slide-up');
        toggleBtn.style.transform = 'scale(1)';
    });

    // 4. Handle Messaging Logic
    function sendMessage() {
        const text = chatInput.value.trim();
        if (!text) return;

        // Add User Message
        appendMessage(text, 'user');
        chatInput.value = '';

        // Simulate Typing Indicator
        const typingId = 'typing-' + Date.now();
        appendMessage('<i class="fas fa-ellipsis-h typing-animation"></i>', 'bot', typingId);

        // Process Bot Response after slight delay
        setTimeout(() => {
            const typingElement = document.getElementById(typingId);
            if (typingElement) typingElement.remove();

            const response = getBotResponse(text.toLowerCase());
            appendMessage(response, 'bot');
        }, 1000 + Math.random() * 1000); // Random delay 1s-2s
    }

    sendBtn.addEventListener('click', sendMessage);
    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    // 5. Append message to UI
    function appendMessage(text, sender, id = null) {
        const msgDiv = document.createElement('div');
        msgDiv.className = `message ${sender}-message`;
        if (id) msgDiv.id = id;
        msgDiv.innerHTML = text;
        messagesContainer.appendChild(msgDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight; // Scroll to bottom
    }

    // 6. Simple Keyword-Based Conversation Engine
    function getBotResponse(input) {
        if (input.includes('register') || input.includes('complaint') || input.includes('report')) {
            return `To register a complaint, click the "Report an Incident" button on the <a href="index.html" style="color:white; text-decoration:underline;">main page</a>. You must create an account first to securely track it, but you have the option to hide your identity in the form!`;
        }
        else if (input.includes('safe') || input.includes('anonymous') || input.includes('privacy')) {
            return `Your safety is our priority. You can check the "Make my complaint Anonymous" box on the reporting form. We will only share details with authorized police personnel.`;
        }
        else if (input.includes('emergency') || input.includes('help') || input.includes('call') || input.includes('number')) {
            return `🚨 For immediate emergencies in Tamil Nadu, call:<br>
                    <strong>100</strong> (Police)<br>
                    <strong>181</strong> (Women Helpline)<br>
                    <strong>1098</strong> (Child Helpline)<br>
                    <strong>1930</strong> (Cyber Crime)`;
        }
        else if (input.includes('counsel') || input.includes('trauma') || input.includes('doctor') || input.includes('therapy')) {
            return `We offer free, confidential trauma recovery counseling with Govt. Specialists. You can book an online or in-person session under the "Trauma Recovery Counseling" section in your <a href="dashboard.html" style="color:white; text-decoration:underline;">Dashboard</a>.`;
        }
        else if (input.includes('hi') || input.includes('hello') || input.includes('vanakkam')) {
            return `Hello! Vanakkam 🙏. I am the TN Assistant. Ask me how to file a complaint, about privacy guarantees, or emergency contacts.`;
        }
        else if (input.includes('track') || input.includes('status')) {
            return `You can track the status of all your submitted complaints securely on your personal <a href="dashboard.html" style="color:white; text-decoration:underline;">Dashboard</a>.`;
        }
        else {
            return `I'm sorry, I'm just a simple assistant and didn't quite understand. Could you rephrase? You can ask about "registering a complaint", "emergency numbers", or "counseling booking". For immediate physical danger, please call 100.`;
        }
    }
});

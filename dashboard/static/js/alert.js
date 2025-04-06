document.addEventListener("DOMContentLoaded", function () {
  const alertBadge = document.getElementById("alert-badge");
  const alertCount = document.getElementById("alert-count");
  const alertList = document.getElementById("alert-list");
  let criticalAlertCount = 0;

  async function checkAnomaly() {
      try {
          let response = await fetch("/check-anomalies");  // Updated API endpoint
          let data = await response.json();

          if (data.status !== "no_anomalies" && data.anomalies.length > 0) {
              alertBadge.textContent = "⚠️ Alert: Potential Threat Detected!";
              alertBadge.classList.remove("safe");
              alertBadge.classList.add("danger");

              criticalAlertCount += data.anomalies.length;
              alertCount.textContent = criticalAlertCount;

              data.anomalies.forEach(addRecentAlert);
          } else {
              console.log("no anomalies")
              alertBadge.textContent = "✅ Safe System";
              alertBadge.classList.remove("danger");
              alertBadge.classList.add("safe");
          }
      } catch (error) {
          console.error("Error checking anomaly:", error);
      }
  }

  function addRecentAlert(anomaly) {
      const alertItem = document.createElement("li");
      alertItem.classList.add("alert-item");

      alertItem.innerHTML = `
          <strong>ID:</strong> ${anomaly.id} | 
          <strong>Protocol:</strong> ${anomaly.proto} | 
          <strong>State:</strong> ${anomaly.state} |
          <strong>Attack Category:</strong> ${anomaly.attack_cat || "Unknown"} <br>
          <strong>Packets:</strong> Sent: ${anomaly.spkts}, Received: ${anomaly.dpkts} | 
          <strong>Bytes:</strong> Sent: ${anomaly.sbytes}, Received: ${anomaly.dbytes} <br>
          <strong>Rate:</strong> ${anomaly.rate} | 
          <strong>Duration:</strong> ${anomaly.dur}s <br>
          <strong>Status:</strong> ${anomaly.label === "0" ? "Normal" : "Threat Detected"} 
      `;

      alertList.prepend(alertItem);
  }

  setInterval(checkAnomaly, 5000);
});


document.getElementById("chatbot-toggle").addEventListener("click", function() {
  let chatbot = document.getElementById("chatbot-container");
  chatbot.style.display = chatbot.style.display === "none" ? "block" : "none";
});

document.getElementById("send-btn").addEventListener("click", function() {
  sendMessage();
});

async function sendMessage() {
  const inputField = document.getElementById("chat-input");
  const message = inputField.value.trim();
  if (!message) return;

  addChatMessage("User", message);
  inputField.value = "";

  try {
      let response = await fetch("/chatbot", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: message })
      });

      let data = await response.json();
      addChatMessage("Chatbot", data.response);
  } catch (error) {
      console.error("Chatbot Error:", error);
      addChatMessage("Chatbot", "Sorry, something went wrong.");
  }
}

function addChatMessage(sender, text) {
  const chatWindow = document.getElementById("chat-window");
  const messageElement = document.createElement("div");
  messageElement.innerHTML = `<strong>${sender}:</strong> ${text}`;
  chatWindow.appendChild(messageElement);
  chatWindow.scrollTop = chatWindow.scrollHeight;
}

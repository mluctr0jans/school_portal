const form = document.querySelector("#login-form");
const statusMessage = document.querySelector("#status");
const accountPanel = document.querySelector("#account");

function readCookie(name) {
  const prefix = `${encodeURIComponent(name)}=`;
  const cookie = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(prefix));
  return cookie ? decodeURIComponent(cookie.slice(prefix.length)) : "";
}

function showAccount(user) {
  document.querySelector("#account-name").textContent = user.username;
  document.querySelector("#account-role").textContent = user.role;
  document.querySelector("#token").textContent = readCookie("access_token");
  accountPanel.hidden = false;
  form.hidden = true;
  statusMessage.textContent = "";
}

async function loadAccount() {
  const response = await fetch("/api/me");
  if (response.ok) {
    const result = await response.json();
    showAccount(result.user);
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  statusMessage.textContent = "Signing in…";
  const values = new FormData(form);
  const response = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: values.get("username"), password: values.get("password") }),
  });
  const result = await response.json();
  if (!response.ok) {
    statusMessage.textContent = result.error || "Sign in failed.";
    return;
  }
  showAccount(result.user);
}
);

document.querySelector("#logout").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" });
  accountPanel.hidden = true;
  form.hidden = false;
  form.reset();
  statusMessage.textContent = "You have signed out.";
});

loadAccount();

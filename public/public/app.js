let csrfToken = "";

async function api(url, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...options.headers
  };

  if (options.method && options.method !== "GET") {
    headers["x-csrf-token"] = csrfToken;
  }

  const response = await fetch(url, {
    ...options,
    headers,
    credentials: "same-origin"
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || "Request failed.");
  }

  return data;
}

async function refreshCsrf() {
  const data = await api("/api/csrf");
  csrfToken = data.csrfToken;
}

function showPage(id) {
  document.querySelectorAll(".page").forEach(page => {
    page.classList.toggle("active", page.id === id);
  });

  document.getElementById("nav").hidden = id === "login";
}

async function loadDashboard() {
  const data = await api("/api/me");

  document.getElementById("clientName").textContent =
    data.user.full_name;

  document.getElementById("balance").textContent =
    new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: "USD"
    }).format(data.balanceCents / 100);
}

document.querySelectorAll("[data-page]").forEach(button => {
  button.addEventListener("click", () => {
    showPage(button.dataset.page);
  });
});

document.getElementById("loginForm").addEventListener("submit",
async event => {
  event.preventDefault();

  const form = Object.fromEntries(new FormData(event.target));

  try {
    await api("/api/login", {
      method: "POST",
      body: JSON.stringify(form)
    });

    await refreshCsrf();
    await loadDashboard();
    showPage("dashboard");
  } catch (error) {
    document.getElementById("loginError").textContent =
      error.message;
  }
});

document.getElementById("withdrawForm").addEventListener("submit",
async event => {
  event.preventDefault();

  const form = Object.fromEntries(new FormData(event.target));

  try {
    const result = await api("/api/withdrawals", {
      method: "POST",
      body: JSON.stringify({
        ...form,
        amountCents: Math.round(Number(form.amount) * 100)
      })
    });

    document.getElementById("withdrawMessage").textContent =
      `Request ${result.requestId} received. ${result.message}`;
  } catch (error) {
    document.getElementById("withdrawMessage").textContent =
      error.message;
  }
});

document.getElementById("logout").addEventListener("click",
async () => {
  await api("/api/logout", {
    method: "POST",
    body: "{}"
  });

  await refreshCsrf();
  showPage("login");
});

refreshCsrf().catch(console.error);

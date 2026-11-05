"use strict";

const form = document.querySelector("#login-form");
const username = document.querySelector("#username");
const password = document.querySelector("#password");
const submit = document.querySelector("#login-button");
const errorMessage = document.querySelector("#login-error");
const loginView = document.querySelector("#login-view");
const accountView = document.querySelector("#account-view");
const adminView = document.querySelector("#admin-view");
const main = document.querySelector("#main");
const details = document.querySelector("#sql-details");
const feedback = document.querySelector("#admin-feedback");
const tbody = document.querySelector("#users-body");
const versionInputs = [...document.querySelectorAll('[name="version"]')];
let mode = "vulnerable";
let session = null;
let users = [];
let editingId = null;
let busy = false;

function setBusy(value) {
  busy = value;
  for (const control of document.querySelectorAll('button, [name="version"], .table-input')) {
    control.disabled = value || (control.hasAttribute("data-edit-user") && editingId !== null);
  }
  form.setAttribute("aria-busy", String(value));
}

async function api(path, { method = "GET", body } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && session) headers["X-CSRF-Token"] = session.csrf_token;
  let response;
  try {
    response = await fetch(path, {
      method, headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
  } catch (error) {
    throw new Error(error.name === "TimeoutError"
      ? "Server neodpovedá. Skúste to znova."
      : "Server nie je dostupný. Skúste to znova.");
  }
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(data.error || "Požiadavka sa nepodarila.");
    error.status = response.status;
    throw error;
  }
  return data;
}

function showLogin() {
  loginView.hidden = false;
  accountView.hidden = true;
  adminView.hidden = true;
  main.classList.remove("admin-layout");
  errorMessage.hidden = true;
  document.querySelector("#account-error").hidden = true;
  feedback.hidden = true;
  details.hidden = true;
  details.open = false;
  users = [];
  editingId = null;
  tbody.replaceChildren();
  document.title = "Prihlásenie — Katedra";
}

function notify(message, isError = false) {
  feedback.textContent = message;
  feedback.dataset.error = String(isError);
  feedback.hidden = false;
}

function handleAdminError(error) {
  if (error.status === 401 || error.status === 403) {
    session = null;
    showLogin();
    errorMessage.textContent = error.message;
    errorMessage.hidden = false;
  } else {
    notify(error.message, true);
  }
}

function cell(value) {
  const td = document.createElement("td");
  td.textContent = value;
  return td;
}

function action(label, callback) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "row-action";
  button.textContent = label;
  button.addEventListener("click", callback);
  return button;
}

function renderUsers() {
  tbody.replaceChildren();
  for (const user of users) {
    const row = document.createElement("tr");
    row.dataset.userId = user.id;
    row.append(cell(user.id), cell(user.username));
    const editing = editingId === user.id;
    const inputs = {};
    for (const [field, label, max] of [["display_name", "Meno", 100], ["email", "E-mail", 150], ["study_group", "Skupina", 30]]) {
      const td = document.createElement("td");
      if (editing) {
        const input = document.createElement("input");
        input.className = "table-input";
        input.type = field === "email" ? "email" : "text";
        input.maxLength = max;
        input.required = field !== "study_group";
        input.value = user[field];
        input.setAttribute("aria-label", `${label}: ${user.username}`);
        input.dataset.field = field;
        inputs[field] = input;
        td.append(input);
      } else {
        td.textContent = user[field] || "—";
      }
      row.append(td);
    }
    row.append(cell(user.role));
    const controls = document.createElement("td");
    if (editing) {
      row.classList.add("editing");
      controls.append(
        action("Uložiť", () => saveUser(user, inputs)),
        action("Zrušiť", () => { editingId = null; renderUsers(); setBusy(false); }),
      );
    } else {
      const edit = action("Upraviť", () => {
        editingId = user.id;
        feedback.hidden = true;
        renderUsers();
        setBusy(false);
        tbody.querySelector(".table-input").focus();
      });
      edit.dataset.editUser = user.id;
      controls.append(edit);
    }
    row.append(controls);
    tbody.append(row);
  }
  setBusy(busy);
}

async function saveUser(user, inputs) {
  if (busy) return;
  for (const input of Object.values(inputs)) {
    if (!input.reportValidity()) return;
  }
  const payload = Object.fromEntries(Object.entries(inputs).map(([key, input]) => [key, input.value.trim()]));
  setBusy(true);
  feedback.hidden = true;
  try {
    const result = await api(`/api/admin/users/${user.id}`, { method: "PATCH", body: payload });
    users = users.map(item => item.id === user.id ? result.user : item);
    if (session.user.id === user.id) session.user = result.user;
    editingId = null;
    renderUsers();
    notify(`Údaje používateľa ${user.username} boli uložené.`);
  } catch (error) {
    handleAdminError(error);
  } finally {
    setBusy(false);
  }
}

async function showAccount() {
  loginView.hidden = true;
  const user = session.user;
  const isAdmin = user.role === "administrátor";
  accountView.hidden = isAdmin;
  adminView.hidden = !isAdmin;
  main.classList.toggle("admin-layout", isAdmin);
  document.title = isAdmin ? "Používatelia — Katedra" : "Môj účet — Katedra";
  if (isAdmin) {
    document.querySelector("#admin-username").textContent = user.username;
    try {
      const data = await api("/api/admin/users");
      users = data.users;
      renderUsers();
      document.querySelector("#admin-title").focus();
    } catch (error) {
      handleAdminError(error);
    }
  } else {
    for (const [id, value] of [["account-title", user.display_name], ["account-username", user.username], ["account-role", user.role], ["account-email", user.email], ["account-group", user.study_group || "—"]]) {
      document.getElementById(id).textContent = value;
    }
    document.querySelector("#account-title").focus();
  }
}

async function logout(clearPassword = true) {
  await api("/api/logout", { method: "POST", body: {} });
  session = null;
  if (clearPassword) password.value = "";
  showLogin();
}

for (const radio of versionInputs) {
  radio.addEventListener("change", async () => {
    const previousMode = mode;
    setBusy(true);
    try {
      await logout(false);
      mode = radio.value;
    } catch (error) {
      for (const input of versionInputs) input.checked = input.value === previousMode;
      if (session?.user.role === "administrátor") notify(error.message, true);
      else { errorMessage.textContent = error.message; errorMessage.hidden = false; }
    } finally {
      setBusy(false);
    }
  });
}

for (const input of [username, password]) {
  input.addEventListener("input", () => { errorMessage.hidden = true; details.hidden = true; });
}

document.querySelector("#show-password").addEventListener("click", (event) => {
  const visible = password.type === "password";
  password.type = visible ? "text" : "password";
  event.currentTarget.textContent = visible ? "Skryť" : "Ukázať";
  event.currentTarget.setAttribute("aria-label", visible ? "Skryť heslo" : "Zobraziť heslo");
  event.currentTarget.setAttribute("aria-pressed", String(visible));
});

for (const button of document.querySelectorAll("[data-logout]")) {
  button.addEventListener("click", async () => {
    setBusy(true);
    try {
      await logout();
      username.focus();
    } catch (error) {
      if (session?.user.role === "administrátor") notify(error.message, true);
      else {
        const message = document.querySelector("#account-error");
        message.textContent = error.message;
        message.hidden = false;
      }
    } finally { setBusy(false); }
  });
}

document.querySelector("#reset-users").addEventListener("click", async () => {
  setBusy(true);
  feedback.hidden = true;
  try {
    const data = await api("/api/admin/reset", { method: "POST", body: {} });
    users = data.users;
    editingId = null;
    session.user = users.find(user => user.id === session.user.id);
    renderUsers();
    notify("Pôvodné údaje boli obnovené.");
  } catch (error) { handleAdminError(error); }
  finally { setBusy(false); }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy) return;
  setBusy(true);
  submit.firstChild.textContent = "Prihlasujem… ";
  errorMessage.hidden = true;
  details.hidden = true;
  try {
    const result = await api("/api/login", {
      method: "POST", body: { username: username.value, password: password.value, mode },
    });
    session = result.authenticated ? { user: result.user, mode: result.mode, csrf_token: result.csrf_token } : null;
    document.querySelector("#sql-query").textContent = result.query;
    const parameters = document.querySelector("#sql-parameters");
    parameters.textContent = `Parametre: ${JSON.stringify(result.parameters)}`;
    parameters.hidden = mode !== "secure";
    const sqlError = document.querySelector("#sql-error");
    sqlError.textContent = result.error || "";
    sqlError.hidden = !result.error;
    details.hidden = false;
    if (session) {
      await showAccount();
    } else {
      errorMessage.textContent = result.status === "error" ? "Prihlásenie sa nepodarilo." : "Nesprávne meno alebo heslo.";
      errorMessage.hidden = false;
    }
  } catch (error) {
    errorMessage.textContent = error.message;
    errorMessage.hidden = false;
  } finally {
    setBusy(false);
    submit.firstChild.textContent = "Prihlásiť sa ";
  }
});

async function restoreSession() {
  setBusy(true);
  try {
    const current = await api("/api/session");
    if (current.authenticated) {
      session = current;
      mode = current.mode;
      for (const input of versionInputs) input.checked = input.value === mode;
      await showAccount();
    }
  } catch (error) {
    errorMessage.textContent = error.message;
    errorMessage.hidden = false;
  } finally { setBusy(false); }
}

restoreSession();

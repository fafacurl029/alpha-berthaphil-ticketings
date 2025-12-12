import { api } from "./api.js";
import { UI } from "./ui.js";
import { me, logout } from "./auth.js";

const $ = (id)=>document.getElementById(id);
const qs = (sel)=>document.querySelector(sel);

let currentUser = null;
let currentTicketId = null;

function roleLevel(role){
  const map = { EMPLOYEE:1, L1:10, L2:20, L3:30, SUPERVISOR:50, ADMIN:99 };
  return map[role] || 0;
}

async function init(){
  currentUser = await me();
  if(!currentUser){
    location.href = "/login.html";
    return;
  }
  $("meName").textContent = `${currentUser.name} (${currentUser.role})`;
  $("meMeta").textContent = `${currentUser.team} • ${currentUser.shift}`;
  $("btnLogout").addEventListener("click", async ()=>{
    await logout();
    location.href="/login.html";
  });

  const meta = await api("/api/meta");
  $("metaShift").textContent = `Current shift (PH): ${meta.currentShiftPH}`;

  setupNav();
  await loadTickets();
  bindForms(meta);

  // default tab
  showTab(currentUser.role === "EMPLOYEE" ? "tabMy" : "tabQueue");
}

function setupNav(){
  const isEmployee = currentUser.role === "EMPLOYEE";
  const isAdmin = currentUser.role === "ADMIN";

  qs('[data-tab="tabMy"]').style.display = "inline-block";
  qs('[data-tab="tabNew"]').style.display = "inline-block";

  qs('[data-tab="tabQueue"]').style.display = isEmployee ? "none" : "inline-block";
  qs('[data-tab="tabReports"]').style.display = isEmployee ? "none" : "inline-block";
  qs('[data-tab="tabUsers"]').style.display = isAdmin ? "inline-block" : "none";

  document.querySelectorAll(".tab").forEach(t=>{
    t.addEventListener("click", ()=> showTab(t.dataset.tab));
  });
}

function showTab(id){
  document.querySelectorAll("[data-view]").forEach(v => v.style.display = "none");
  $(id).style.display = "block";
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === id));
  if(id==="tabUsers") loadUsers();
  if(id==="tabReports") loadReports();
  if(id==="tabQueue" || id==="tabMy") loadTickets();
}

function ticketRow(t){
  return `
    <tr data-id="${t.id}">
      <td><span class="badge">${UI.esc(t.humanId)}</span></td>
      <td><div style="font-weight:900">${UI.esc(t.subject)}</div><div class="muted" style="font-size:12px">${UI.esc(t.category)} / ${UI.esc(t.subcategory)}</div></td>
      <td>${UI.pillStatus(t.status)}</td>
      <td>${UI.pillPriority(t.priority)}</td>
      <td class="muted">${UI.esc(t.requester?.email || "")}</td>
      <td class="muted">${UI.esc(t.assignedTo?.email || "—")}</td>
      <td class="muted">${UI.fmtDate(t.updatedAt)}</td>
    </tr>
  `;
}

function ticketCard(t){
  return `
    <div class="listCard" data-id="${t.id}">
      <div class="listCardTop">
        <div>
          <div class="listCardId">${UI.esc(t.humanId)}</div>
          <div class="listCardSubject">${UI.esc(t.subject)}</div>
          <div class="muted" style="font-size:12px;margin-top:4px">${UI.esc(t.category)} / ${UI.esc(t.subcategory)}</div>
        </div>
        <div class="stack">
          ${UI.pillStatus(t.status)}
          ${UI.pillPriority(t.priority)}
        </div>
      </div>
      <div class="listCardMeta">
        <div class="metaPair"><span class="metaKey">Requester</span><span class="metaVal">${UI.esc(t.requester?.email||"")}</span></div>
        <div class="metaPair"><span class="metaKey">Assigned</span><span class="metaVal">${UI.esc(t.assignedTo?.email||"—")}</span></div>
      </div>
      <div class="listCardFoot">
        <span>Updated: ${UI.fmtDate(t.updatedAt)}</span>
      </div>
    </div>
  `;
}

async function loadTickets(){
  const isEmployee = currentUser.role === "EMPLOYEE";
  const activeTab = document.querySelector(".tab.active")?.dataset?.tab || (isEmployee ? "tabMy" : "tabQueue");
  const isMy = activeTab === "tabMy";

  const bodyEl = document.getElementById(isMy ? "ticketsBodyMy" : "ticketsBodyQueue");
  const cardsEl = document.getElementById(isMy ? "ticketsCardsMy" : "ticketsCardsQueue");

    const mine = (!isEmployee && isMy) ? 1 : 0;

  const q = $("qSearch").value.trim();
  const status = $("qStatus").value;
  const priority = $("qPriority").value;

  const params = new URLSearchParams();
  if(q) params.set("q", q);
  if(status) params.set("status", status);
  if(priority) params.set("priority", priority);
  if(!isEmployee) params.set("mine", String(mine));

  const { tickets } = await api("/api/tickets?" + params.toString());
  bodyEl.innerHTML = tickets.map(ticketRow).join("") || `<tr><td colspan="7" class="muted">No tickets found.</td></tr>`;
  cardsEl.innerHTML = tickets.map(ticketCard).join("") || `<div class="muted">No tickets found.</div>`;

  bodyEl.querySelectorAll("tr[data-id]").forEach(tr=>{
    tr.addEventListener("click", ()=> openTicket(tr.dataset.id));
  });
  cardsEl.querySelectorAll(".listCard[data-id]").forEach(c=>{
    c.addEventListener("click", ()=> openTicket(c.dataset.id));
  });

  // my tickets count
  if(isMy) $("myCount").textContent = tickets.length;
}

async function openTicket(id){
  currentTicketId = id;
  const { ticket } = await api("/api/tickets/" + id);

  $("tdHuman").textContent = ticket.humanId;
  $("tdSubject").textContent = ticket.subject;
  $("tdMeta").textContent = `${ticket.category} / ${ticket.subcategory} • ${ticket.priority} • ${ticket.status}`;
  $("tdReq").textContent = `${ticket.requester?.name || ""} (${ticket.requester?.email || ""})`;
  $("tdAss").textContent = ticket.assignedTo ? `${ticket.assignedTo.name} (${ticket.assignedTo.email})` : "—";
  $("tdSla").textContent = `FR due: ${ticket.slaFirstResponseDue ? UI.fmtDate(ticket.slaFirstResponseDue) : "—"} | RES due: ${ticket.slaResolutionDue ? UI.fmtDate(ticket.slaResolutionDue) : "—"}`;

  $("ticketDesc").textContent = ticket.description;

  // comments
  const isEmployee = currentUser.role === "EMPLOYEE";
  const comments = ticket.comments || [];
  $("comments").innerHTML = comments.map(c => {
    if(c.isInternal && isEmployee) return "";
    return `
      <div class="card" style="box-shadow:none;padding:10px 12px;margin-bottom:10px;background:rgba(0,0,0,.22)">
        <div class="muted" style="font-size:12px;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap">
          <span>${UI.esc(c.author?.name || "")} • ${UI.esc(c.author?.role || "")} ${c.isInternal ? "• INTERNAL" : ""}</span>
          <span>${UI.fmtDate(c.createdAt)}</span>
        </div>
        <div style="margin-top:8px;white-space:pre-wrap">${UI.esc(c.body)}</div>
      </div>
    `;
  }).filter(Boolean).join("") || `<div class="muted">No comments yet.</div>`;

  // audit (IT only)
  const auditWrap = $("auditWrap");
  if(isEmployee){
    auditWrap.style.display = "none";
  } else {
    auditWrap.style.display = "block";
    $("audit").innerHTML = (ticket.auditLogs || []).slice(0,30).map(a => `
      <div class="muted" style="font-size:12px;margin:6px 0">
        ${UI.fmtDate(a.createdAt)} • <b style="color:var(--text)">${UI.esc(a.actor?.name||"")}</b> • ${UI.esc(a.action)}
      </div>
    `).join("") || `<div class="muted">No audit events.</div>`;
  }

  // actions
  renderActions(ticket);

  // show drawer
  $("ticketPanel").style.display = "block";
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function renderActions(ticket){
  const isEmployee = currentUser.role === "EMPLOYEE";
  $("itActions").style.display = isEmployee ? "none" : "block";
  $("empActions").style.display = isEmployee ? "block" : "none";
  $("commentInternal").disabled = isEmployee;
  $("commentInternal").closest('label').style.display = isEmployee ? 'none' : 'flex';

  if(!isEmployee){
    $("itStatus").value = ticket.status;
    $("itPriority").value = ticket.priority;

    // Close restrictions
    const canClose = roleLevel(currentUser.role) >= roleLevel("L3");
    [...$("itStatus").options].forEach(o=>{
      if(o.value==="CLOSED") o.disabled = !canClose;
    });

    // priority change restrictions
    const canChangePriority = roleLevel(currentUser.role) >= roleLevel("L2");
    $("itPriority").disabled = !canChangePriority;
  }
}

function bindForms(meta){
  // filters
  $("btnSearch").addEventListener("click", loadTickets);

  // new ticket
  $("newImpact").innerHTML = meta.impacts.map(x=>`<option value="${x}">${x}</option>`).join("");
  $("newUrgency").innerHTML = meta.urgencies.map(x=>`<option value="${x}">${x}</option>`).join("");

  $("formNew").addEventListener("submit", async (e)=>{
    e.preventDefault();
    try{
      const payload = {
        subject: $("newSubject").value.trim(),
        description: $("newDesc").value.trim(),
        category: $("newCategory").value.trim(),
        subcategory: $("newSub").value.trim(),
        impact: $("newImpact").value,
        urgency: $("newUrgency").value
      };
      const { ticket } = await api("/api/tickets", { method:"POST", body: JSON.stringify(payload) });
      UI.toast("Ticket created: " + ticket.humanId);
      $("formNew").reset();
      showTab("tabMy");
      await loadTickets();
      await openTicket(ticket.id);
    }catch(err){
      UI.toast(err.message);
    }
  });

  // comment
  $("formComment").addEventListener("submit", async (e)=>{
    e.preventDefault();
    if(!currentTicketId) return;
    try{
      const body = $("commentBody").value.trim();
      const isInternal = $("commentInternal").checked;
      await api(`/api/tickets/${currentTicketId}/comments`, { method:"POST", body: JSON.stringify({ body, isInternal }) });
      $("commentBody").value = "";
      $("commentInternal").checked = false;
      UI.toast("Comment added");
      openTicket(currentTicketId);
    }catch(err){ UI.toast(err.message); }
  });

  // IT update
  $("btnUpdateTicket").addEventListener("click", async ()=>{
    if(!currentTicketId) return;
    try{
      const status = $("itStatus").value;
      const priority = $("itPriority").value;
      const slaPaused = $("itSlaPaused").checked;
      const slaPauseReason = $("itSlaReason").value.trim() || null;

      await api(`/api/tickets/${currentTicketId}`, { method:"PATCH", body: JSON.stringify({ status, priority, slaPaused, slaPauseReason }) });
      UI.toast("Ticket updated");
      await loadTickets();
      await openTicket(currentTicketId);
    }catch(err){ UI.toast(err.message); }
  });

  // escalate
  $("btnEscalate").addEventListener("click", async ()=>{
    if(!currentTicketId) return;
    try{
      const reason = prompt("Escalation reason (required):");
      if(!reason || reason.trim().length < 3) return;

      const toLevel = prompt("Escalate to level: L2 or L3", "L2");
      if(!["L2","L3"].includes(String(toLevel||"").toUpperCase())) {
        UI.toast("Invalid level");
        return;
      }

      const toTeam = prompt("Team: SERVICE_DESK/NETWORK/SYSTEMS/SECURITY/APPLICATION/FIELD", "NETWORK");
      if(!meta.teams.includes(String(toTeam||"").toUpperCase())) {
        UI.toast("Invalid team");
        return;
      }

      await api(`/api/tickets/${currentTicketId}/escalate`, { method:"POST", body: JSON.stringify({ reason: reason.trim(), toLevel: String(toLevel).toUpperCase(), toTeam: String(toTeam).toUpperCase() }) });
      UI.toast("Escalated");
      await loadTickets();
      await openTicket(currentTicketId);
    }catch(err){ UI.toast(err.message); }
  });

  
// admin user create
const isAdmin = currentUser.role === "ADMIN";
const usersTab = document.querySelector('[data-tab="tabUsers"]');
if(isAdmin){
  document.getElementById("formUserCreate")?.addEventListener("submit", async (e)=>{
    e.preventDefault();
    try{
      const payload = {
        name: document.getElementById("ucName").value.trim(),
        email: document.getElementById("ucEmail").value.trim(),
        role: document.getElementById("ucRole").value,
        team: document.getElementById("ucTeam").value,
        shift: document.getElementById("ucShift").value,
        password: document.getElementById("ucPass").value
      };
      await api("/api/users", { method:"POST", body: JSON.stringify(payload) });
      UI.toast("User created");
      document.getElementById("formUserCreate").reset();
      await loadUsers();
    }catch(err){ UI.toast(err.message); }
  });
  document.getElementById("ucClear")?.addEventListener("click", ()=>{
    document.getElementById("formUserCreate").reset();
  });
}

  // employee reopen
  $("btnReopen").addEventListener("click", async ()=>{
    if(!currentTicketId) return;
    const reason = prompt("Why are you reopening this ticket?");
    if(!reason || reason.trim().length < 3) return;
    try{
      await api(`/api/tickets/${currentTicketId}/reopen`, { method:"POST", body: JSON.stringify({ reason: reason.trim() }) });
      UI.toast("Ticket reopened");
      await loadTickets();
      await openTicket(currentTicketId);
    }catch(err){ UI.toast(err.message); }
  });
}

async function loadUsers(){
  try{
    const { users } = await api("/api/users");
    $("usersBody").innerHTML = users.map(u => `
      <tr>
        <td>
          <b>${UI.esc(u.name)}</b>
          <div class="muted" style="font-size:12px">${UI.esc(u.email)}</div>
        </td>
        <td>${UI.esc(u.role)}</td>
        <td>${UI.esc(u.team)}</td>
        <td>${UI.esc(u.shift)}</td>
        <td>${u.active ? `<span class="pill"><span class="dot ok"></span>Active</span>` : `<span class="pill"><span class="dot bad"></span>Disabled</span>`}</td>
        <td>
          <button class="btn secondary small" data-u-toggle="${u.id}">${u.active ? "Disable" : "Enable"}</button>
          <button class="btn secondary small" data-u-reset="${u.id}">Reset PW</button>
        </td>
      </tr>
    `).join("") || `<tr><td colspan="6" class="muted">No users.</td></tr>`;

    document.querySelectorAll("[data-u-toggle]").forEach(btn=>{
      btn.addEventListener("click", async ()=>{
        const id = btn.getAttribute("data-u-toggle");
        const active = btn.textContent.trim() === "Enable";
        try{
          await api("/api/users/"+id, { method:"PATCH", body: JSON.stringify({ active }) });
          UI.toast(active ? "Enabled" : "Disabled");
          loadUsers();
        }catch(err){ UI.toast(err.message); }
      });
    });

    document.querySelectorAll("[data-u-reset]").forEach(btn=>{
      btn.addEventListener("click", async ()=>{
        const id = btn.getAttribute("data-u-reset");
        const pw = prompt("New password (min 8 chars):");
        if(!pw || pw.length < 8) return;
        try{
          await api("/api/users/"+id+"/reset-password", { method:"POST", body: JSON.stringify({ password: pw }) });
          UI.toast("Password reset");
        }catch(err){ UI.toast(err.message); }
      });
    });

  }catch(err){
    UI.toast(err.message);
  }
}

async function loadReports(){
  try{
    const data = await api("/api/reports/summary");
    $("repTotalOpen").textContent = data.totalOpen;
    $("repShift").textContent = data.currentShiftPH;

    $("repByStatus").innerHTML = (data.byStatus || []).map(x=>`<div class="item"><b>${x.status}</b>: ${x._count.status}</div>`).join("") || "";
    $("repByPriority").innerHTML = (data.byPriority || []).map(x=>`<div class="item"><b>${x.priority}</b>: ${x._count.priority}</div>`).join("") || "";
    $("repExport").href = "/api/reports/export.csv";
  }catch(err){ UI.toast(err.message); }
}

init();

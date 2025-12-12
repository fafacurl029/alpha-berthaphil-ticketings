export const UI = {
  esc(s){ return String(s ?? "").replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m])); },
  toast(msg){
    const t = document.createElement("div");
    t.className = "toast";
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(()=> t.remove(), 2600);
  },
  pillStatus(status){
    const map = {
      NEW:["warn","New"],
      ASSIGNED:["warn","Assigned"],
      IN_PROGRESS:["ok","In progress"],
      WAITING_ON_USER:["warn","Waiting user"],
      WAITING_ON_VENDOR:["warn","Waiting vendor"],
      ESCALATED:["bad","Escalated"],
      RESOLVED:["ok","Resolved"],
      CLOSED:["ok","Closed"]
    };
    const [c,label] = map[status] || ["warn", status];
    const dot = c==="ok"?"ok":(c==="bad"?"bad":"warn");
    return `<span class="pill"><span class="dot ${dot}"></span>${label}</span>`;
  },
  pillPriority(p){
    const map = { P1:["bad","P1"], P2:["warn","P2"], P3:["warn","P3"], P4:["ok","P4"] };
    const [c,label] = map[p] || ["warn", p];
    const dot = c==="ok"?"ok":(c==="bad"?"bad":"warn");
    return `<span class="pill"><span class="dot ${dot}"></span>${label}</span>`;
  },
  fmtDate(d){
    try { return new Date(d).toLocaleString(); } catch { return String(d||""); }
  }
};

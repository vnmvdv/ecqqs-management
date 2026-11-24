// Owner-only user administration for EverClean QQS management.
// Actions: invite (email or shareable link), link (new password-setup link), delete.
import { createClient } from "npm:@supabase/supabase-js@2";

const APP_URL = "https://ecqqs-management.netlify.app/";
const ROLES = ["owner", "manager", "cleaner", "client", "accountant"];
const DEV_ROLES: Record<string, string> = { manager: "Мениджър", cleaner: "Хигиенист", client: "Клиент", accountant: "Счетоводител" };

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });
const fail = (message: string, status = 400) => json({ error: message }, status);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return fail("Method not allowed", 405);

  const url = Deno.env.get("SUPABASE_URL")!;
  const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  // Who is calling? Must be an active owner.
  const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  const { data: who, error: whoErr } = await admin.auth.getUser(token);
  if (whoErr || !who?.user) return fail("Не сте влезли в системата.", 401);
  const { data: me } = await admin.from("profiles").select("role,status,is_dev").eq("id", who.user.id).maybeSingle();
  if (!me || me.role !== "owner" || me.status !== "active" || me.is_dev) return fail("Само собственик може да управлява потребители.", 403);

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return fail("Невалидна заявка."); }
  const action = String(body.action || "");

  try {
    if (action === "invite") {
      const email = String(body.email || "").trim().toLowerCase();
      const role = String(body.role || "");
      const delivery = body.delivery === "email" ? "email" : "link";
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return fail("Невалиден имейл.");
      if (!ROLES.includes(role)) return fail("Изберете роля.");

      const { data: existing } = await admin.from("profiles").select("id").eq("email", email).maybeSingle();
      if (existing) return fail("Вече има потребител с този имейл.");

      let userId: string;
      let link: string | null = null;
      if (delivery === "email") {
        const { data, error } = await admin.auth.admin.inviteUserByEmail(email, { redirectTo: APP_URL });
        if (error) throw error;
        userId = data.user.id;
      } else {
        const { data, error } = await admin.auth.admin.generateLink({ type: "invite", email, options: { redirectTo: APP_URL } });
        if (error) throw error;
        userId = data.user.id;
        link = data.properties.action_link;
      }

      const { error: upErr } = await admin.from("profiles").update({
        fname: String(body.fname || "").trim() || null,
        lname: String(body.lname || "").trim() || null,
        phone: String(body.phone || "").trim() || null,
        role,
        status: "active",
      }).eq("id", userId);
      if (upErr) throw upErr;

      return json({ ok: true, user_id: userId, link });
    }

    if (action === "link") {
      const userId = String(body.user_id || "");
      const { data: target } = await admin.auth.admin.getUserById(userId);
      if (!target?.user?.email) return fail("Потребителят не е намерен.", 404);
      // Never confirmed → fresh invite link; otherwise a password-setup (recovery) link
      const type = target.user.email_confirmed_at ? "recovery" : "invite";
      const { data, error } = await admin.auth.admin.generateLink({
        type, email: target.user.email, options: { redirectTo: APP_URL },
      } as never);
      if (error) throw error;
      return json({ ok: true, link: data.properties.action_link, type });
    }

    if (action === "dev_switch") {
      // Owner-only: sign in as a test account of the given role (created on first use)
      const role = String(body.role || "");
      if (!DEV_ROLES[role]) return fail("Непозната роля.");
      const email = `dev-${role}@example.com`;
      let { data: prof } = await admin.from("profiles").select("id").eq("email", email).maybeSingle();
      if (!prof) {
        const pw = crypto.randomUUID() + crypto.randomUUID(); // never shown; access only via this switch
        const { data, error } = await admin.auth.admin.createUser({ email, password: pw, email_confirm: true });
        if (error) throw error;
        prof = { id: data.user.id };
      }
      const { error: upErr } = await admin.from("profiles").update({
        role, status: "active", is_dev: true, fname: "Тест", lname: DEV_ROLES[role],
      }).eq("id", prof.id);
      if (upErr) throw upErr;
      const { data: link, error: lErr } = await admin.auth.admin.generateLink({ type: "magiclink", email });
      if (lErr) throw lErr;
      return json({ ok: true, token_hash: link.properties.hashed_token, email });
    }

    if (action === "delete") {
      const userId = String(body.user_id || "");
      if (userId === who.user.id) return fail("Не можете да изтриете собствения си акаунт.");
      const { data: target } = await admin.from("profiles").select("role,status").eq("id", userId).maybeSingle();
      if (target?.role === "owner" && target?.status === "active") {
        const { count } = await admin.from("profiles").select("id", { count: "exact", head: true })
          .eq("role", "owner").eq("status", "active").neq("id", userId);
        if (!count) return fail("Трябва да остане поне един активен собственик.");
      }
      const { error } = await admin.auth.admin.deleteUser(userId);
      if (error) throw error;
      return json({ ok: true });
    }

    return fail("Непознато действие.");
  } catch (e) {
    const msg = (e as { message?: string })?.message || "";
    if (/already been registered|already registered|exists/i.test(msg)) return fail("Вече има потребител с този имейл.");
    if (/rate limit/i.test(msg)) return fail("Достигнат е лимитът за имейли. Използвайте „Линк за споделяне“ или опитайте по-късно.", 429);
    console.error(action, msg);
    return fail("Възникна грешка: " + msg, 500);
  }
});
